import json
import re
from pathlib import Path


PLAYBOOK_DIR = Path(__file__).resolve().parent / "playbooks"


class PlaybookNotFoundError(ValueError):
    """
    Raised when an alert cannot be mapped to a trusted SOC playbook.
    """

ALERT_TITLE_PLAYBOOKS = {
    "ssh brute force detection": "ssh_bruteforce.json",
    "sql injection detection": "sql_injection.json",
    "test observables sql injection detection": "sql_injection.json",
    "o365 mass sharing link creation": "o365_mass_sharing.json",
}

RULE_ID_PLAYBOOKS = {
    "custom-ssh-bruteforce-threshold": "ssh_bruteforce.json",
    "custom-sql-injection-detection": "sql_injection.json",
    "custom-o365-mass-sharing-link-creation": "o365_mass_sharing.json",
}

TAG_PLAYBOOKS = {
    "uc-ssh-001": "ssh_bruteforce.json",
    "uc-sqli-001": "sql_injection.json",
    "uc-o365-001": "o365_mass_sharing.json",
}


def load_playbook(file_name: str) -> dict:
    playbook_path = PLAYBOOK_DIR / file_name

    with open(playbook_path, "r", encoding="utf-8") as file:
        return json.load(file)


def normalize_alert_title(value: str) -> str:
    """
    Normalize alert names so prefixes like "TEST -" do not break playbook selection.
    """

    normalized = value.lower()
    normalized = re.sub(r"[^a-z0-9]+", " ", normalized)
    normalized = re.sub(r"\btest\b", " ", normalized)
    normalized = re.sub(r"\bobservables?\b", " ", normalized)
    return " ".join(normalized.split())


def get_alert_title(alert: dict) -> str:
    return str(
        alert.get("title")
        or alert.get("name")
        or alert.get("rule", {}).get("name")
        or alert.get("kibana", {}).get("alert", {}).get("rule", {}).get("name")
        or alert.get("signal", {}).get("rule", {}).get("name")
        or ""
    )


def get_nested_value(payload: dict, paths: list[tuple[str, ...]]) -> str:
    for path in paths:
        current = payload
        for key in path:
            if not isinstance(current, dict):
                current = None
                break
            current = current.get(key)

        if current:
            return str(current)

    return ""


def get_alert_rule_id(alert: dict) -> str:
    return get_nested_value(
        alert,
        [
            ("rule", "id"),
            ("kibana", "alert", "rule", "uuid"),
            ("kibana", "alert", "rule", "rule_id"),
            ("signal", "rule", "id"),
            ("signal", "rule", "rule_id"),
            ("raw_data", "signal", "rule", "id"),
            ("rawData", "signal", "rule", "id"),
        ],
    ).lower()


def get_alert_tags(alert: dict) -> set[str]:
    tags = alert.get("tags") or []
    if not isinstance(tags, list):
        return set()

    return {str(tag).strip().lower() for tag in tags if str(tag).strip()}


def select_playbook(alert: dict) -> dict:
    """
    Select the SOC playbook from stable identifiers first, then tags, then title.
    """

    rule_id = get_alert_rule_id(alert)
    if rule_id in RULE_ID_PLAYBOOKS:
        return load_playbook(RULE_ID_PLAYBOOKS[rule_id])

    tags = get_alert_tags(alert)
    for tag, playbook_file in TAG_PLAYBOOKS.items():
        if tag in tags:
            return load_playbook(playbook_file)

    alert_title = normalize_alert_title(get_alert_title(alert))

    if alert_title in ALERT_TITLE_PLAYBOOKS:
        return load_playbook(ALERT_TITLE_PLAYBOOKS[alert_title])

    for known_title, playbook_file in ALERT_TITLE_PLAYBOOKS.items():
        if known_title in alert_title:
            return load_playbook(playbook_file)

    raise PlaybookNotFoundError(
        f"No matching playbook found for alert title: {alert_title or 'Unknown'}"
    )


def select_playbook_from_content(alert: dict) -> dict:
    """
    Fallback selector for alerts that do not expose a stable title.
    """

    description = str(alert.get("description", "")).lower()
    raw_data = str(alert.get("raw_data", alert.get("rawData", {}))).lower()
    searchable_text = f"{description} {raw_data}"

    if (
        "ssh brute force" in searchable_text
        or "ssh bruteforce" in searchable_text
        or "failed password" in searchable_text
        or "authentication failure" in searchable_text
    ):
        return load_playbook("ssh_bruteforce.json")

    if (
        "sql injection" in searchable_text
        or "sqli" in searchable_text
        or "sqlmap" in searchable_text
        or "union select" in searchable_text
        or "or 1=1" in searchable_text
    ):
        return load_playbook("sql_injection.json")

    if (
        "o365" in searchable_text
        or "office 365" in searchable_text
        or "sharepoint" in searchable_text
        or "onedrive" in searchable_text
        or "sharinglinkcreated" in searchable_text
        or "sharing link" in searchable_text
        or "mass sharing" in searchable_text
    ):
        return load_playbook("o365_mass_sharing.json")

    raise PlaybookNotFoundError("No matching playbook found for this alert.")
