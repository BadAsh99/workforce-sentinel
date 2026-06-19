"""Vulnerability matching with KEV-weighted (threat-intel) prioritization."""

import re


def _nums(version):
    parts = [int(x) for x in re.findall(r"\d+", version)]
    while len(parts) < 4:
        parts.append(0)
    return parts


def _affected(version, rule):
    rule = rule.strip()
    if rule.startswith("<"):
        return _nums(version) < _nums(rule[1:])
    if rule.endswith("*"):
        return version.startswith(rule[:-1])
    return version == rule


def _severity(cve):
    if cve.get("kev"):
        return "critical"
    score = cve.get("cvss", 0)
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def scan(inventory, cve_feed):
    findings = []
    for device in inventory:
        for software in device.get("installed", []):
            for cve in cve_feed:
                if software["name"] == cve["product"] and _affected(software["version"], cve["affected"]):
                    findings.append({
                        "type": "vuln",
                        "device_id": device["device_id"],
                        "hostname": device.get("hostname"),
                        "product": software["name"],
                        "version": software["version"],
                        "cve": cve["cve"],
                        "name": cve.get("name"),
                        "cvss": cve.get("cvss"),
                        "kev": bool(cve.get("kev")),
                        "severity": _severity(cve),
                        "description": f"{cve['cve']} ({cve.get('name')}) in {software['name']} {software['version']}",
                    })
    return findings
