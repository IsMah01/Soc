import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from app import (
    BASE_DIR,
    normalize_thehive_alert_id,
    prepare_prompt_from_alert,
    save_output,
)
from config import Config
from cortex_client import CortexClient
from llm_client import LLMClient
from observable_extractor import (
    extract_enrichment_reports,
    simplify_observables,
)
from playbook_selector import PlaybookNotFoundError
from report_writer import build_markdown_report, build_playbook_not_found_comment
from thehive_client import TheHiveClient


TERMINAL_JOB_STATUSES = {"Success", "Failure", "Deleted"}


def state_path() -> Path:
    path = Path(Config.AUTO_STATE_FILE)
    if not path.is_absolute():
        path = BASE_DIR / path
    return path


def state_exists() -> bool:
    path = state_path()
    return path.exists()


def load_state() -> set[str]:
    path = state_path()
    if not state_exists():
        return set()

    with open(path, "r", encoding="utf-8") as file:
        payload = json.load(file)

    return set(payload.get("processed_alert_ids", []))


def save_state(processed_alert_ids: set[str]):
    path = state_path()
    path.parent.mkdir(exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(
            {
                "processed_alert_ids": sorted(processed_alert_ids),
                "updated_at": int(time.time()),
            },
            file,
            indent=2
        )


def is_processable_alert(alert: dict) -> bool:
    if alert.get("status") != "New":
        return False

    tags = set(alert.get("tags", []))
    if "ai-soc-auto-processed" in tags:
        return False

    return True


def analyzer_already_present(observable: dict, analyzer_name: str) -> bool:
    reports = observable.get("reports") or {}
    return analyzer_name in reports


def compatible_analyzers(analyzers: list[dict], observable: dict) -> list[dict]:
    data_type = observable.get("dataType")
    allowed_names = Config.auto_analyzer_names()

    if data_type in {"other", "hostname"}:
        return []

    matches = []
    for analyzer in analyzers:
        name = analyzer.get("name")
        if name not in allowed_names:
            continue
        if data_type not in analyzer.get("dataTypeList", []):
            continue
        if analyzer_already_present(observable, name):
            continue

        matches.append(analyzer)

    return matches


def wait_for_cortex_job_id(hive: TheHiveClient, hive_job: dict) -> str | None:
    job_id = hive_job.get("_id") or hive_job.get("id")
    cortex_job_id = hive_job.get("cortexJobId")

    if cortex_job_id and cortex_job_id != "-":
        return cortex_job_id

    deadline = time.time() + 30
    while time.time() < deadline:
        time.sleep(2)
        refreshed = hive.get_cortex_job(job_id)
        cortex_job_id = refreshed.get("cortexJobId")
        if cortex_job_id and cortex_job_id != "-":
            return cortex_job_id

    return None


def wait_for_cortex_report(
    cortex: CortexClient,
    cortex_job_id: str
) -> dict | None:
    deadline = time.time() + Config.AUTO_ANALYZER_WAIT_SECONDS

    while time.time() < deadline:
        report = cortex.get_job_report(cortex_job_id)
        status = report.get("status")

        if status in TERMINAL_JOB_STATUSES:
            return report

        time.sleep(Config.AUTO_ANALYZER_POLL_SECONDS)

    return None


def run_analyzers(
    hive: TheHiveClient,
    cortex: CortexClient,
    observables: list[dict],
    analyzers: list[dict]
) -> list[dict]:
    tasks = []

    for observable in observables:
        observable_id = observable.get("_id")
        if not observable_id:
            continue

        for analyzer in compatible_analyzers(analyzers, observable):
            tasks.append(
                {
                    "observable": observable,
                    "analyzer": analyzer,
                }
            )

    if not tasks:
        return []

    print(f"[+] Launching Cortex analyzers in parallel: {len(tasks)} jobs")

    def run_one(task: dict) -> dict | None:
        observable = task["observable"]
        analyzer = task["analyzer"]
        observable_id = observable.get("_id")
        analyzer_name = analyzer.get("name")
        target = f"{observable.get('dataType')}={observable.get('data')}"

        print(f"[+] Running analyzer {analyzer_name} on {target}")

        hive_job = hive.run_cortex_analyzer(
            observable_id=observable_id,
            analyzer_id=analyzer["id"],
            cortex_id=(analyzer.get("cortexIds") or ["local"])[0]
        )
        cortex_job_id = wait_for_cortex_job_id(hive, hive_job)
        if not cortex_job_id:
            print(f"[WARNING] No Cortex job id returned for {analyzer_name}")
            return None

        cortex_report = wait_for_cortex_report(cortex, cortex_job_id)
        if not cortex_report:
            print(f"[WARNING] Timed out waiting for {analyzer_name} on {target}")
            return None

        if cortex_report.get("status") != "Success":
            print(
                "[WARNING] Analyzer did not complete successfully: "
                f"{analyzer_name} status={cortex_report.get('status')}"
            )
            return None

        return {
            "observable_id": observable_id,
            "dataType": observable.get("dataType"),
            "data": observable.get("data"),
            "reports": {
                analyzer_name: cortex_report.get("report", {}).get("summary", {})
            },
        }

    reports = []
    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures = [executor.submit(run_one, task) for task in tasks]
        for future in as_completed(futures):
            try:
                report = future.result()
            except Exception as error:
                print(f"[WARNING] Analyzer task failed: {error}")
                continue

            if report:
                reports.append(report)

    return reports


def process_alert(
    hive: TheHiveClient,
    cortex: CortexClient,
    analyzers: list[dict],
    alert_id: str
):
    alert_id = normalize_thehive_alert_id(alert_id)
    print(f"[+] Processing alert {alert_id}")

    alert = hive.get_alert(alert_id)
    raw_observables = hive.get_alert_observables(alert_id)
    observables = simplify_observables(raw_observables)
    existing_reports = extract_enrichment_reports(raw_observables)

    analyzer_reports = run_analyzers(hive, cortex, raw_observables, analyzers)
    enrichment_reports = existing_reports + analyzer_reports

    try:
        prompt = prepare_prompt_from_alert(alert, observables, enrichment_reports)
    except PlaybookNotFoundError as error:
        report = build_playbook_not_found_comment(alert, str(error))
        output_name = f"{alert_id.replace('~', '')}_playbook_not_found.md"
        save_output(report, output_name)

        print("[+] Writing playbook-not-found comment back to TheHive...")
        hive.add_alert_comment(alert_id, report)
        print("[+] Playbook-not-found comment added as TheHive comment.")
        return

    analysis = LLMClient().analyze_alert(prompt)
    report = build_markdown_report(analysis)

    output_name = f"{alert_id.replace('~', '')}_ai_report.md"
    save_output(report, output_name)

    print("[+] Writing AI report back to TheHive...")
    hive.add_alert_comment(alert_id, report)
    print("[+] AI report added as TheHive comment.")


def run_once():
    Config.validate(require_llm=True, require_thehive=True)
    if not Config.CORTEX_API_KEY:
        raise ValueError("CORTEX_API_KEY is required for automation.")

    hive = TheHiveClient(Config.THEHIVE_URL, Config.THEHIVE_API_KEY)
    cortex = CortexClient(Config.CORTEX_URL, Config.CORTEX_API_KEY)
    analyzers = hive.list_cortex_analyzers()
    processed = load_state()

    alerts = hive.list_alerts(Config.AUTO_ALERT_RANGE)

    if not state_exists() and not Config.AUTO_PROCESS_EXISTING:
        processed.update(
            alert["_id"]
            for alert in alerts
            if alert.get("_id")
        )
        save_state(processed)
        print(
            "[+] Automation state initialized with existing alerts. "
            "New alerts will be processed on the next cycle."
        )
        return

    candidates = [
        alert for alert in alerts
        if is_processable_alert(alert)
        and alert.get("_id") not in processed
    ]

    print(f"[+] Processable alerts found: {len(candidates)}")

    for alert in candidates:
        alert_id = alert["_id"]
        try:
            process_alert(hive, cortex, analyzers, alert_id)
            processed.add(alert_id)
            save_state(processed)
        except Exception as error:
            print(f"[ERROR] Failed to process {alert_id}: {error}")


def run_forever():
    while True:
        run_once()
        print(f"[+] Sleeping {Config.AUTO_POLL_INTERVAL}s")
        time.sleep(Config.AUTO_POLL_INTERVAL)


def main():
    parser = argparse.ArgumentParser(
        description="Automate TheHive -> Cortex analyzers -> AI SOC Assistant"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one automation cycle and exit"
    )

    args = parser.parse_args()

    if args.once:
        run_once()
    else:
        run_forever()


if __name__ == "__main__":
    main()
