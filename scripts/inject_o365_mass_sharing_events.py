#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timedelta, timezone

import requests


ELASTIC_URL = "http://localhost:9200"
AUTH = ("elastic", "<REMOVED_DEFAULT_PASSWORD>")


def iso_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_event(ts: datetime, sequence: int, run_id: str) -> dict:
    file_name = f"Finance_Report_Q2_part_{sequence:02d}.xlsx"
    file_path = f"/sites/Finance/Shared Documents/{file_name}"
    url_full = f"https://contoso.sharepoint.com/sites/Finance/Shared%20Documents/{file_name}"

    return {
        "@timestamp": iso_z(ts),
        "event": {
            "kind": "event",
            "category": ["file", "web"],
            "type": ["creation", "access"],
            "action": "SharingLinkCreated",
            "provider": "SharePoint",
            "outcome": "success",
            "dataset": "o365.audit",
        },
        "http": {
            "request": {"method": "POST"},
            "response": {"status_code": 200},
        },
        "user": {
            "email": "employee@example.com",
            "name": "employee",
        },
        "source": {
            "ip": "45.155.91.12",
            "geo": {
                "country_name": "Netherlands",
                "city_name": "Amsterdam",
            },
        },
        "destination": {
            "ip": "20.190.160.10",
        },
        "user_agent": {
            "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Office365Shell/16.0",
        },
        "o365": {
            "audit": {
                "Operation": "SharingLinkCreated",
                "Workload": "SharePoint",
                "UserId": "employee@example.com",
                "ObjectId": url_full.replace("%20", " "),
                "ResultStatus": "Succeeded",
                "ClientIP": "45.155.91.12",
                "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Office365Shell/16.0",
                "CreationTime": iso_z(ts),
                "TargetUserOrGroupName": "external.partner@example.net",
            }
        },
        "file": {
            "name": file_name,
            "path": file_path,
        },
        "url": {
            "full": url_full,
            "domain": "contoso.sharepoint.com",
        },
        "sharing": {
            "count": 30,
            "scope": "External",
            "link_type": "Anonymous",
            "external_recipient_count": 14,
        },
        "device": {
            "name": "Unknown-Device",
        },
        "session": {
            "status": "Unknown",
        },
        "data": {
            "sensitivity": "Confidential",
        },
        "tags": [
            "uc-o365-001",
            "cloud",
            "m365",
            "sharepoint",
            "onedrive",
            "mass-sharing",
            run_id,
        ],
        "message": (
            "O365 SharePoint external anonymous sharing link created by "
            "employee@example.com for confidential finance document"
        ),
    }


def main():
    parser = argparse.ArgumentParser(description="Inject O365 mass sharing events.")
    parser.add_argument("--index", default="logs-custom-default")
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--run-id", default=f"o365-mass-sharing-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
    args = parser.parse_args()

    start = datetime.now(timezone.utc)
    # Keep all documents inside the rule lookback, with slight timestamp variation.
    first_event_ts = start - timedelta(seconds=max(args.count, 30))

    lines = []
    for i in range(args.count):
        doc_id = f"{args.run_id}-{i + 1:03d}"
        lines.append(json.dumps({"create": {"_index": args.index, "_id": doc_id}}))
        lines.append(json.dumps(build_event(first_event_ts + timedelta(seconds=i), i + 1, args.run_id)))

    body = "\n".join(lines) + "\n"
    response = requests.post(
        f"{ELASTIC_URL}/_bulk",
        auth=AUTH,
        headers={"Content-Type": "application/x-ndjson"},
        data=body,
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()

    refresh = requests.post(f"{ELASTIC_URL}/{args.index}/_refresh", auth=AUTH, timeout=30)
    refresh.raise_for_status()

    end = datetime.now(timezone.utc)
    print(json.dumps({
        "run_id": args.run_id,
        "index": args.index,
        "count": args.count,
        "bulk_errors": payload.get("errors"),
        "injection_start_utc": iso_z(start),
        "first_event_timestamp_utc": iso_z(first_event_ts),
        "last_event_timestamp_utc": iso_z(first_event_ts + timedelta(seconds=args.count - 1)),
        "injection_end_utc": iso_z(end),
        "duration_seconds": round((end - start).total_seconds(), 3),
        "sample_doc_id": f"{args.run_id}-001",
    }, indent=2))


if __name__ == "__main__":
    main()
