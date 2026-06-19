"""Minimal SOAR engine: match findings against declarative playbooks, emit actions."""


def _matches(finding, match):
    if "type" in match and finding.get("type") != match["type"]:
        return False
    if "severity_in" in match and finding.get("severity") not in match["severity_in"]:
        return False
    if "control" in match and finding.get("control") != match["control"]:
        return False
    if "kev" in match and bool(finding.get("kev")) != bool(match["kev"]):
        return False
    return True


def run(findings, playbooks):
    actions = []
    for finding in findings:
        for playbook in playbooks:
            if _matches(finding, playbook.get("match", {})):
                for action in playbook.get("actions", []):
                    actions.append({
                        "playbook": playbook["name"],
                        "device_id": finding.get("device_id"),
                        "finding": finding.get("description"),
                        "action": action,
                    })
    return actions
