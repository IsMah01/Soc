#!/usr/bin/env python3
import json
import argparse
from pathlib import Path

import requests


BASE_DIR = Path(__file__).resolve().parents[1]
RULE_PATH = BASE_DIR / "ai-soc-assistant" / "rules" / "o365_mass_sharing_elastic_rule.json"
BEFORE_TUNING_RULE_PATH = (
    BASE_DIR
    / "ai-soc-assistant"
    / "rules"
    / "o365_mass_sharing_elastic_rule_before_tuning.json"
)

KIBANA_URL = "http://localhost:5601"
AUTH = ("elastic", "<REMOVED_DEFAULT_PASSWORD>")
HEADERS = {
    "kbn-xsrf": "true",
    "Content-Type": "application/json",
}
EXCEPTION_LIST_ID = "o365-mass-sharing-approved-sources"


def load_rule(rule_path: Path) -> dict:
    with open(rule_path, "r", encoding="utf-8") as file:
        source = json.load(file)

    return {
        "rule_id": source["rule_id"],
        "name": source["name"],
        "description": source["description"],
        "type": source["type"],
        "enabled": source["enabled"],
        "severity": source["severity"],
        "risk_score": source["risk_score"],
        "interval": source["interval"],
        "from": source["from"],
        "to": "now",
        "index": source["index"],
        "language": source["language"],
        "query": source["query"],
        "threshold": source["threshold"],
        "tags": source["tags"],
        "threat": source.get("threat", []),
        "exceptions_list": source.get("exceptions_list", []),
        "author": ["AI SOC Assistant"],
        "false_positives": [
            "Bulk collaboration during a legitimate project",
            "Approved SharePoint migration or automation",
            "Expected mass sharing by business teams with documented justification",
        ],
        "references": [],
        "note": (
            "Use case UC-O365-001. Investigate sharing.count, sharing.scope, "
            "sharing.link_type, data.sensitivity, source.ip, device.name and session.status."
        ),
    }


def request(method: str, path: str, **kwargs) -> requests.Response:
    return requests.request(
        method,
        f"{KIBANA_URL}{path}",
        auth=AUTH,
        headers=HEADERS,
        timeout=30,
        **kwargs,
    )


def ensure_exception_list():
    response = request(
        "POST",
        "/api/exception_lists",
        json={
            "name": "O365 Mass Sharing - Approved Sources",
            "description": (
                "Approved IP ranges and domains excluded from the O365 mass sharing "
                "detection rule after SOC validation."
            ),
            "list_id": EXCEPTION_LIST_ID,
            "type": "detection",
            "namespace_type": "single",
            "tags": ["uc-o365-001", "approved-exceptions"],
        },
    )

    if response.status_code not in (200, 201, 409):
        raise SystemExit(
            f"Failed to create exception list: HTTP {response.status_code} {response.text}"
        )


def ensure_exception_item(item: dict):
    response = request("POST", "/api/exception_lists/items", json=item)

    if response.status_code not in (200, 201, 409):
        raise SystemExit(
            f"Failed to create exception item {item.get('item_id')}: "
            f"HTTP {response.status_code} {response.text}"
        )


def ensure_tuned_exceptions():
    ensure_exception_list()

    base = {
        "list_id": EXCEPTION_LIST_ID,
        "namespace_type": "single",
        "type": "simple",
        "tags": ["uc-o365-001", "approved-exception"],
    }

    ensure_exception_item({
        **base,
        "item_id": "approved-corporate-ip-ranges",
        "name": "Approved corporate IP ranges",
        "description": "Exclude validated corporate/private source IP ranges.",
        "entries": [
            {
                "field": "source.ip",
                "operator": "included",
                "type": "match_any",
                "value": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
            }
        ],
    })

    ensure_exception_item({
        **base,
        "item_id": "approved-sharepoint-domains",
        "name": "Approved SharePoint tenant domains",
        "description": "Exclude validated tenant domains used by approved workflows.",
        "entries": [
            {
                "field": "url.domain",
                "operator": "included",
                "type": "match_any",
                "value": ["organization.sharepoint.com", "organization-my.sharepoint.com"],
            }
        ],
    })

    ensure_exception_item({
        **base,
        "item_id": "approved-partner-domain-pattern",
        "name": "Approved partner domain pattern",
        "description": "Example wildcard for a validated trusted partner domain.",
        "entries": [
            {
                "field": "url.domain",
                "operator": "included",
                "type": "wildcard",
                "value": "*.trusted-partner.example",
            }
        ],
    })


def main():
    parser = argparse.ArgumentParser(description="Upsert O365 Elastic detection rule.")
    parser.add_argument(
        "--profile",
        choices=["tuned", "before-tuning"],
        default="tuned",
        help="Rule version to push to Kibana.",
    )
    args = parser.parse_args()

    rule_path = RULE_PATH if args.profile == "tuned" else BEFORE_TUNING_RULE_PATH
    rule = load_rule(rule_path)
    rule_id = rule["rule_id"]

    if args.profile == "tuned" and rule.get("exceptions_list"):
        ensure_tuned_exceptions()

    existing = request("GET", f"/api/detection_engine/rules?rule_id={rule_id}")

    if existing.status_code == 200:
        response = request("PATCH", "/api/detection_engine/rules", json=rule)
        action = "updated"
    elif existing.status_code == 404:
        response = request("POST", "/api/detection_engine/rules", json=rule)
        action = "created"
    else:
        raise SystemExit(
            f"Failed to check rule existence: HTTP {existing.status_code} {existing.text}"
        )

    if response.status_code not in (200, 201):
        raise SystemExit(
            f"Failed to {action.rstrip('d')} rule: HTTP {response.status_code} {response.text}"
        )

    data = response.json()
    print(json.dumps({
        "action": action,
        "id": data.get("id"),
        "rule_id": data.get("rule_id"),
        "name": data.get("name"),
        "enabled": data.get("enabled"),
        "severity": data.get("severity"),
        "risk_score": data.get("risk_score"),
        "interval": data.get("interval"),
        "from": data.get("from"),
        "threshold": data.get("threshold"),
        "tags": data.get("tags"),
        "threat": data.get("threat"),
        "exceptions_list": data.get("exceptions_list"),
    }, indent=2))


if __name__ == "__main__":
    main()
