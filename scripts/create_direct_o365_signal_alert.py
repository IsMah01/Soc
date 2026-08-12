#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timezone

import requests


ELASTIC_URL = "http://localhost:9200"
AUTH = ("elastic", "<REMOVED_DEFAULT_PASSWORD>")


def iso_z() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_alert(run_id: str, malicious_email: bool = False) -> dict:
    now = iso_z()
    url_full = "https://contoso.sharepoint.com/sites/Finance/Shared%20Documents/Finance_Report_Q2.xlsx"
    user_email = "employee@example.com"
    external_recipient = "external.partner@example.net"
    threat_indicator = None

    if malicious_email:
        external_recipient = "exfil.operator@malicious.example"
        threat_indicator = {
            "email": {
                "address": external_recipient,
            },
            "type": "email-addr",
            "provider": "SOC test intelligence",
            "confidence": "High",
            "description": (
                "Known malicious external email used in the O365 mass sharing "
                "exfiltration simulation."
            ),
        }

    alert = {
        "@timestamp": now,
        "event": {
            "kind": "signal",
            "category": ["file", "web"],
            "type": ["creation", "alert"],
            "action": "SharingLinkCreated",
            "provider": "SharePoint",
            "outcome": "success",
            "dataset": "o365.audit",
            "module": "o365",
        },
        "signal": {
            "status": "open",
            "rule": {
                "id": "custom-o365-mass-sharing-link-creation",
                "rule_id": "custom-o365-mass-sharing-link-creation",
                "name": "O365 Mass Sharing Link Creation",
                "type": "manual-direct-signal",
                "severity": "medium",
                "risk_score": 47,
                "description": (
                    "Detects abnormal mass creation of Microsoft 365 SharePoint "
                    "or OneDrive sharing links by the same user from the same source IP."
                ),
            },
            "reason": (
                "Direct O365 alert: 30 external anonymous SharePoint sharing links "
                f"created by {user_email} from 45.155.91.12."
            ),
            "threshold_result": {
                "count": 30,
                "terms": [
                    {"field": "user.email", "value": user_email},
                    {"field": "source.ip", "value": "45.155.91.12"},
                ],
            },
        },
        "rule": {
            "name": "O365 Mass Sharing Link Creation",
        },
        "http": {
            "request": {"method": "POST"},
            "response": {"status_code": 200},
        },
        "user": {
            "email": user_email,
            "name": "employee",
            "id": user_email,
        },
        "source": {
            "ip": "45.155.91.12",
            "geo": {
                "country_name": "Netherlands",
                "city_name": "Amsterdam",
            },
        },
        "client": {
            "ip": "45.155.91.12",
        },
        "destination": {
            "ip": "20.190.160.10",
        },
        "related": {
            "ip": ["45.155.91.12", "20.190.160.10"],
        },
        "user_agent": {
            "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Office365Shell/16.0",
        },
        "o365": {
            "audit": {
                "Operation": "SharingLinkCreated",
                "Workload": "SharePoint",
                "UserId": user_email,
                "ObjectId": url_full.replace("%20", " "),
                "ResultStatus": "Succeeded",
                "ClientIP": "45.155.91.12",
                "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Office365Shell/16.0",
                "CreationTime": now,
                "TargetUserOrGroupName": external_recipient,
            }
        },
        "file": {
            "name": "Finance_Report_Q2.xlsx",
            "path": "/sites/Finance/Shared Documents/Finance_Report_Q2.xlsx",
        },
        "url": {
            "original": url_full,
            "full": url_full,
            "domain": "contoso.sharepoint.com",
            "path": "/sites/Finance/Shared Documents/Finance_Report_Q2.xlsx",
        },
        "host": {
            "name": "O365-SharePoint",
        },
        "device": {
            "name": "Unknown-Device",
        },
        "observer": {
            "hostname": "o365-audit-collector",
        },
        "sharing": {
            "count": 30,
            "scope": "External",
            "link_type": "Anonymous",
            "external_recipient_count": 14,
        },
        "session": {
            "status": "Unknown",
        },
        "data": {
            "sensitivity": "Confidential",
        },
        "message": (
            "O365 Mass Sharing Link Creation: 30 external anonymous SharePoint "
            "sharing links created for confidential finance documents."
        ),
        "tags": [
            "uc-o365-001",
            "cloud",
            "m365",
            "sharepoint",
            "onedrive",
            "mass-sharing",
            "direct-signal-test",
            run_id,
        ],
    }

    if malicious_email and threat_indicator:
        alert["threat"] = {
            "indicator": threat_indicator,
        }
        alert["message"] = (
            "O365 Mass Sharing Link Creation: 30 external anonymous SharePoint "
            "sharing links created for confidential finance documents and sent "
            f"to known malicious external recipient {external_recipient}."
        )
        alert["signal"]["rule"]["severity"] = "high"
        alert["signal"]["rule"]["risk_score"] = 78
        alert["tags"].extend(["malicious-email", "ioc-email", "known-bad-recipient"])

    return alert


def main():
    parser = argparse.ArgumentParser(description="Create direct O365 signal alert.")
    parser.add_argument("--index", default=".siem-signals-default-000004")
    parser.add_argument("--run-id", default=f"o365-direct-signal-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
    parser.add_argument(
        "--malicious-email",
        action="store_true",
        help="Use a known malicious external recipient email indicator.",
    )
    args = parser.parse_args()

    alert = build_alert(args.run_id, malicious_email=args.malicious_email)
    doc_id = args.run_id
    start = iso_z()
    response = requests.post(
        f"{ELASTIC_URL}/{args.index}/_doc/{doc_id}",
        auth=AUTH,
        json=alert,
        timeout=30,
    )
    response.raise_for_status()
    requests.post(f"{ELASTIC_URL}/{args.index}/_refresh", auth=AUTH, timeout=30).raise_for_status()

    print(json.dumps({
        "run_id": args.run_id,
        "index": args.index,
        "doc_id": doc_id,
        "created_at_utc": start,
        "elastic_status": response.status_code,
        "result": response.json().get("result"),
        "expected_observable_count_from_sync": "rich alert fields available",
    }, indent=2))


if __name__ == "__main__":
    main()
