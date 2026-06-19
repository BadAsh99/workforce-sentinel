"""CIS-style host-hardening checks (macOS Benchmark-aligned subset).

Each control mirrors a real CIS macOS Benchmark item: what to enforce, why it
matters (rationale), and how to remediate. Level 1 = practical safe baseline.
This is the layer an MDM (Jamf / Intune) enforces and HIP / posture validates.
"""

MACOS_CONTROLS = [
    {"id": "CIS 2.5.1", "level": 1, "severity": "high", "title": "Enable FileVault (full-disk encryption)",
     "check": lambda c: c.get("filevault") is True,
     "rationale": "Encrypts data at rest so a lost or stolen Mac does not leak data.",
     "remediation": "System Settings > Privacy & Security > FileVault > Turn On."},
    {"id": "CIS 2.5.2", "level": 1, "severity": "high", "title": "Enable Gatekeeper",
     "check": lambda c: c.get("gatekeeper") is True,
     "rationale": "Blocks unsigned / untrusted applications from executing.",
     "remediation": "Enforce via MDM, or spctl --global-enable."},
    {"id": "CIS 5.1.1", "level": 1, "severity": "high", "title": "Enable System Integrity Protection (SIP)",
     "check": lambda c: c.get("sip") is True,
     "rationale": "Protects system files and processes from tampering, even by root.",
     "remediation": "Boot to Recovery > Terminal > csrutil enable."},
    {"id": "CIS 2.2.1", "level": 1, "severity": "high", "title": "Enable the application firewall",
     "check": lambda c: c.get("firewall") is True,
     "rationale": "Controls inbound connections and limits network attack surface.",
     "remediation": "System Settings > Network > Firewall > On (enforce via MDM profile)."},
    {"id": "CIS 1.1", "level": 1, "severity": "medium", "title": "Enable automatic security updates",
     "check": lambda c: c.get("auto_updates") is True,
     "rationale": "Closes known vulnerabilities promptly without relying on the user.",
     "remediation": "System Settings > General > Software Update > automatic updates on."},
    {"id": "CIS 2.10.1", "level": 1, "severity": "medium", "title": "Lock screen within 5 minutes of inactivity",
     "check": lambda c: isinstance(c.get("screen_lock_minutes"), int) and c["screen_lock_minutes"] <= 5,
     "rationale": "Limits unauthorized physical access to an unattended, unlocked Mac.",
     "remediation": "Set screen saver / lock to <= 5 minutes and require password immediately."},
    {"id": "CIS 2.3.1", "level": 1, "severity": "high", "title": "Disable Remote Login (SSH)",
     "check": lambda c: c.get("remote_login") is False,
     "rationale": "Remote Login is a remote-access attack surface; disable unless required.",
     "remediation": "System Settings > General > Sharing > Remote Login > Off."},
    {"id": "CIS 2.3.2", "level": 1, "severity": "medium", "title": "Disable unnecessary sharing services",
     "check": lambda c: not c.get("sharing_services"),
     "rationale": "Every enabled sharing service (screen, file, media) widens attack surface.",
     "remediation": "System Settings > General > Sharing > turn off unused services."},
]


def scan(inventory):
    findings = []
    for device in inventory:
        if device.get("platform") != "macos":
            continue
        config = device.get("config", {})
        for control in MACOS_CONTROLS:
            if not control["check"](config):
                findings.append({
                    "type": "hardening",
                    "device_id": device["device_id"],
                    "hostname": device.get("hostname"),
                    "control": control["id"],
                    "level": control["level"],
                    "severity": control["severity"],
                    "description": f"FAIL [{control['id']} L{control['level']}] {control['title']}",
                    "rationale": control["rationale"],
                    "remediation": control["remediation"],
                })
    return findings
