def simplify_observable(observable: dict) -> dict:
    """
    Keep the fields that are useful for SOC analysis and prompt readability.
    """

    useful_fields = [
        "_id",
        "dataType",
        "data",
        "message",
        "tags",
        "tlp",
        "tlpLabel",
        "ioc",
        "sighted",
        "ignoreSimilarity",
        "createdAt",
        "_createdAt",
    ]

    return {
        field: observable[field]
        for field in useful_fields
        if field in observable and observable[field] not in (None, "", [])
    }


def simplify_observables(observables: list[dict]) -> list[dict]:
    return [simplify_observable(observable) for observable in observables]


def extract_enrichment_reports(observables: list[dict]) -> list[dict]:
    """
    Extract non-empty analyzer/Cortex reports attached to TheHive observables.
    """

    enrichment_reports = []

    for observable in observables:
        reports = observable.get("reports")
        if not reports:
            continue

        enrichment_reports.append(
            {
                "observable_id": observable.get("_id"),
                "dataType": observable.get("dataType"),
                "data": observable.get("data"),
                "reports": reports,
            }
        )

    return enrichment_reports
