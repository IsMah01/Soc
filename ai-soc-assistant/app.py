import argparse
import json
from pathlib import Path

from config import Config
from thehive_client import TheHiveClient
from playbook_selector import PlaybookNotFoundError, select_playbook
from report_writer import build_markdown_report, build_playbook_not_found_comment
from observable_extractor import extract_enrichment_reports, simplify_observables


BASE_DIR = Path(__file__).resolve().parent


def load_prompt_template() -> str:
    prompt_path = BASE_DIR / "prompts" / "soc_analysis_prompt.txt"

    with open(prompt_path, "r", encoding="utf-8") as file:
        return file.read()


def load_sample_alert(sample_path: str) -> dict:
    path = Path(sample_path)
    if not path.is_absolute():
        path = BASE_DIR / path

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def build_prompt(
    alert: dict,
    playbook: dict,
    observables: list[dict] | None = None,
    enrichment_reports: list[dict] | None = None
) -> str:
    """
    Build the final prompt sent to the LLM.
    V1 input = raw alert + selected playbook.
    """

    template = load_prompt_template()

    prompt = template.replace(
        "{{ALERT_DATA}}",
        json.dumps(alert, indent=2, ensure_ascii=False)
    )

    prompt = prompt.replace(
        "{{ALERT_OBSERVABLES}}",
        json.dumps(observables or [], indent=2, ensure_ascii=False)
    )

    prompt = prompt.replace(
        "{{ENRICHMENT_REPORTS}}",
        json.dumps(enrichment_reports or [], indent=2, ensure_ascii=False)
    )

    prompt = prompt.replace(
        "{{PLAYBOOK}}",
        json.dumps(playbook, indent=2, ensure_ascii=False)
    )

    return prompt


def save_output(report: str, output_name: str):
    output_dir = Path(Config.OUTPUT_DIR)
    if not output_dir.is_absolute():
        output_dir = BASE_DIR / output_dir
    output_dir.mkdir(exist_ok=True)

    output_path = output_dir / output_name

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(report)

    print(f"[+] Report saved to: {output_path}")


def save_prompt(prompt: str, output_name: str):
    output_dir = Path(Config.OUTPUT_DIR)
    if not output_dir.is_absolute():
        output_dir = BASE_DIR / output_dir
    output_dir.mkdir(exist_ok=True)

    output_path = output_dir / output_name

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(prompt)

    print(f"[+] Prompt saved to: {output_path}")


def prepare_prompt_from_alert(
    alert: dict,
    observables: list[dict] | None = None,
    enrichment_reports: list[dict] | None = None
) -> str:
    """
    Prepare the exact prompt that will be sent to the LLM.
    """

    print("[+] Selecting SOC playbook...")
    playbook = select_playbook(alert)
    print(f"[+] Selected playbook: {playbook.get('name')}")

    print("[+] Building LLM prompt...")
    prompt = build_prompt(alert, playbook, observables, enrichment_reports)

    return prompt


def normalize_thehive_alert_id(alert_id: str) -> str:
    """
    TheHive alert IDs are commonly copied as ~12345. Accept extra/missing tildes.
    """

    clean_id = str(alert_id).strip().lstrip("~")
    if not clean_id:
        raise ValueError("TheHive alert ID is empty.")

    return f"~{clean_id}"


def analyze_alert_object(
    alert: dict,
    observables: list[dict] | None = None,
    enrichment_reports: list[dict] | None = None
) -> str:
    """
    Main V1 analysis logic:
    alert + playbook -> LLM -> report.
    """

    prompt = prepare_prompt_from_alert(alert, observables, enrichment_reports)

    print("[+] Sending alert to LLM...")
    from llm_client import LLMClient

    llm = LLMClient()
    analysis = llm.analyze_alert(prompt)

    print("[+] Building SOC report...")
    report = build_markdown_report(analysis)

    return report


def analyze_sample(sample_path: str, show_prompt: bool):
    print(f"[+] Loading sample alert: {sample_path}")

    alert = load_sample_alert(sample_path)

    alert_id = str(alert.get("id", "sample_alert")).replace("~", "")

    if show_prompt:
        prompt = prepare_prompt_from_alert(alert)

        print("\n========== PROMPT SENT TO LLM ==========\n")
        print(prompt)

        save_prompt(prompt, f"{alert_id}_prompt.txt")
        return

    report = analyze_alert_object(alert)

    output_name = f"{alert_id}_ai_report.md"
    save_output(report, output_name)

    print("\n========== AI SOC REPORT ==========\n")
    print(report)


def analyze_thehive_alert(alert_id: str, write_back: bool, show_prompt: bool):
    alert_id = normalize_thehive_alert_id(alert_id)
    print(f"[+] Retrieving alert from TheHive: {alert_id}")

    hive = TheHiveClient(
        base_url=Config.THEHIVE_URL,
        api_key=Config.THEHIVE_API_KEY
    )

    alert = hive.get_alert(alert_id)
    print("[+] Retrieving alert observables from TheHive...")
    raw_observables = hive.get_alert_observables(alert_id)
    observables = simplify_observables(raw_observables)
    print(f"[+] Retrieved observables: {len(observables)}")
    print("[+] Extracting enrichment reports from observables...")
    enrichment_reports = extract_enrichment_reports(raw_observables)
    print(f"[+] Retrieved enrichment reports: {len(enrichment_reports)}")

    if show_prompt:
        prompt = prepare_prompt_from_alert(alert, observables, enrichment_reports)

        print("\n========== PROMPT SENT TO LLM ==========\n")
        print(prompt)

        output_name = f"{alert_id.replace('~', '')}_prompt.txt"
        save_prompt(prompt, output_name)
        return

    try:
        report = analyze_alert_object(alert, observables, enrichment_reports)
    except PlaybookNotFoundError as error:
        report = build_playbook_not_found_comment(alert, str(error))

        output_name = f"{alert_id.replace('~', '')}_playbook_not_found.md"
        save_output(report, output_name)

        print("[+] Writing playbook-not-found comment back to TheHive...")
        hive.add_alert_comment(alert_id, report)
        print("[+] Playbook-not-found comment added as TheHive comment.")

        print("\n========== AI SOC ASSISTANT STATUS ==========\n")
        print(report)
        return

    output_name = f"{alert_id.replace('~', '')}_ai_report.md"
    save_output(report, output_name)

    if write_back:
        print("[+] Writing AI report back to TheHive...")
        hive.add_alert_comment(alert_id, report)
        print("[+] AI report added as TheHive comment.")

    print("\n========== AI SOC REPORT ==========\n")
    print(report)


def main():
    parser = argparse.ArgumentParser(
        description="AI-Assisted SOC Alert Analysis - V1"
    )

    parser.add_argument(
        "--sample",
        help="Path to local sample alert JSON file"
    )

    parser.add_argument(
        "--alert-id",
        help="TheHive alert ID, example: ~81924152"
    )

    parser.add_argument(
        "--write-back",
        action="store_true",
        help="Write AI report back to TheHive as a comment"
    )

    parser.add_argument(
        "--show-prompt",
        action="store_true",
        help="Show the exact prompt that will be sent to the LLM without calling the LLM"
    )

    args = parser.parse_args()
    try:
        Config.validate(
            require_llm=not args.show_prompt,
            require_thehive=bool(args.alert_id)
        )
    except ValueError as error:
        parser.error(str(error))

    if args.sample:
        analyze_sample(args.sample, args.show_prompt)

    elif args.alert_id:
        analyze_thehive_alert(args.alert_id, args.write_back, args.show_prompt)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
