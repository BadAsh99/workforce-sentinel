"""Host posture / hardening checks against an internal baseline."""

BASELINE = {
    "disk_encryption": ("Disk encryption (FileVault / BitLocker) enabled", "high"),
    "firewall": ("Host firewall enabled", "medium"),
    "screen_lock": ("Screen lock / auto-lock enabled", "low"),
    "os_up_to_date": ("OS patched to current baseline", "high"),
    "edr_installed": ("EDR agent installed and running", "high"),
}


def check_device(device):
    findings = []
    for control, (desc, severity) in BASELINE.items():
        if not device.get(control, False):
            findings.append({
                "type": "posture",
                "device_id": device["device_id"],
                "hostname": device.get("hostname"),
                "control": control,
                "severity": severity,
                "description": f"FAIL: {desc}",
            })
    return findings


def scan(inventory):
    findings = []
    for device in inventory:
        findings.extend(check_device(device))
    return findings
