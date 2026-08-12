from datetime import datetime


def format_list_item(item) -> str:
    """
    Keep the Markdown report readable even if the LLM returns a structured item.
    """

    if isinstance(item, str):
        return item

    if isinstance(item, dict):
        field = item.get("field")
        value = item.get("value")
        if field and value not in (None, ""):
            return f"{field}: {value}"

        text = item.get("text") or item.get("description") or item.get("summary")
        if text:
            return str(text)

    return str(item)


def build_playbook_not_found_comment(alert: dict, error_message: str) -> str:
    """
    Build the TheHive comment used when no trusted playbook matches an alert.
    """

    title = (
        alert.get("title")
        or alert.get("name")
        or alert.get("rule", {}).get("name")
        or alert.get("kibana", {}).get("alert", {}).get("rule", {}).get("name")
        or alert.get("signal", {}).get("rule", {}).get("name")
        or "Unknown"
    )
    rule_id = (
        alert.get("rule", {}).get("id")
        or alert.get("kibana", {}).get("alert", {}).get("rule", {}).get("uuid")
        or alert.get("kibana", {}).get("alert", {}).get("rule", {}).get("rule_id")
        or alert.get("signal", {}).get("rule", {}).get("id")
        or alert.get("signal", {}).get("rule", {}).get("rule_id")
        or "Unknown"
    )
    tags = alert.get("tags") or []
    if isinstance(tags, list) and tags:
        tags_display = ", ".join(str(tag) for tag in tags)
    else:
        tags_display = "None"

    report = []
    report.append("# AI SOC Assistant - Analysis Not Generated")
    report.append("")
    report.append(f"**Generated at:** {datetime.utcnow().isoformat()} UTC")
    report.append("")
    report.append("**Status:** playbook_not_found")
    report.append(f"**Alert Title:** {title}")
    report.append(f"**Rule ID:** {rule_id}")
    report.append(f"**Tags:** {tags_display}")
    report.append("")
    report.append("## Reason")
    report.append(
        "No matching SOC playbook was found for this alert. "
        "The LLM analysis was not launched to avoid generating a generic "
        "or procedure-inconsistent report."
    )
    report.append("")
    report.append("## Technical Detail")
    report.append(f"- {error_message}")
    report.append("")
    report.append("## Items To Check")
    report.append("- Elastic rule identifier, for example `rule.id` or `signal.rule.id`.")
    report.append("- Functional use-case tags, for example `uc-ssh-001` or `uc-sqli-001`.")
    report.append("- Normalized alert title used by the playbook selector.")
    report.append("- Matching JSON playbook in `ai-soc-assistant/playbooks/`.")
    report.append("")
    report.append("## Recommended Action")
    report.append(
        "Create or map the correct playbook, then relaunch the AI SOC analysis."
    )
    report.append("")

    return "\n".join(report)


def build_markdown_report(analysis: dict) -> str:
    """
    Convert LLM JSON response into a readable SOC report.
    """

    status = analysis.get("status", "success")
    classification = analysis.get("classification", "Unknown")
    confidence = analysis.get("confidence", 0)
    severity = analysis.get("severity_recommendation", "Unknown")
    summary = analysis.get("summary", "No summary provided.")
    evidence = analysis.get("evidence", [])
    actions = analysis.get("recommended_actions", [])
    playbook = analysis.get("playbook_used", "Unknown")
    limitations = analysis.get("limitations", [])

    if isinstance(confidence, float) and 0 <= confidence <= 1:
        confidence_display = f"{round(confidence * 100)}%"
    elif isinstance(confidence, (int, float)):
        confidence_display = f"{round(confidence)}%"
    else:
        confidence_display = str(confidence)

    report = []

    report.append("# AI SOC Analysis Report")
    report.append("")
    report.append(f"**Generated at:** {datetime.utcnow().isoformat()} UTC")
    report.append("")
    report.append(f"**Status:** {status}")
    report.append(f"**Classification:** {classification}")
    report.append(f"**Model Assurance (indicative):** {confidence_display}")
    report.append(f"**Recommended Severity:** {severity}")
    report.append(f"**Playbook Used:** {playbook}")
    report.append("")

    report.append("## Summary")
    report.append(summary)
    report.append("")

    report.append("## Evidence")
    if evidence:
        for item in evidence:
            report.append(f"- {format_list_item(item)}")
    else:
        report.append("- No evidence provided.")
    report.append("")

    report.append("## Recommended Actions")
    if actions:
        for action in actions:
            report.append(f"- {format_list_item(action)}")
    else:
        report.append("- No recommended actions provided.")
    report.append("")

    report.append("## Limitations")
    if limitations:
        for limitation in limitations:
            report.append(f"- {format_list_item(limitation)}")
    else:
        report.append("- No limitation mentioned.")
    report.append("")

    return "\n".join(report)
