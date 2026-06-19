# Workforce Sentinel

A small, dependency-free endpoint security automation demo: it scans a device fleet for **posture / hardening drift**, identifies **vulnerabilities with threat-intel (KEV) prioritization**, and runs a **declarative SOAR playbook engine** that turns findings into automated response actions.

Built as a portfolio piece to demonstrate the concepts an enterprise stack (Cortex XSIAM / XSOAR, Tenable, CrowdStrike) implements at scale. Sample data, mocked actions, real logic.

## Run it

```bash
python3 main.py
```

No dependencies (Python 3 standard library only). Writes a machine-readable `report.json`.

Optional flags: `--inventory`, `--cve`, `--playbooks`, `--report`.

## What it does (maps to endpoint / workforce security)

| Module | What it does | Real-world analog |
|---|---|---|
| `sentinel/posture.py` | Checks each device against an internal hardening baseline (disk encryption, firewall, screen lock, OS patch level, EDR present); flags drift | Host hardening, CIS/STIG-style baselines, config-drift detection |
| `sentinel/vulns.py` | Matches installed software against a CVE feed, version-aware; prioritizes by **KEV** (known-exploited) then CVSS | Vulnerability identification + threat-intel-driven prioritization |
| `sentinel/engine.py` | Loads JSON playbooks and fires actions on matching findings | SOAR (Cortex XSOAR / playbook automation) |
| `playbooks/*.json` | Declarative trigger -> action automation (open ticket, notify, schedule patch, block access, isolate) | SOAR playbooks |
| `main.py` | Orchestrates scan -> findings -> playbooks; severity-weighted risk per device | SecOps reporting / risk scoring |

KEV = CISA Known Exploited Vulnerabilities catalog, the simplest real threat-intel signal: "is this being exploited in the wild right now."

## Design notes

- **Playbooks are data, not code.** A `match` block (type, severity, control, kev) plus an `actions` list. Adding a response = adding a JSON file, no engine changes. This is the core SOAR idea: analysts author automation without writing application code.
- **Device trust in action.** The unencrypted-disk playbook fires `flag_block_access`, modelling how an endpoint that fails its baseline loses its trusted access posture (the HIP / Conditional Access pattern).
- **Threat intel changes priority, not just score.** A KEV hit is treated as critical regardless of raw CVSS, because exploited-in-the-wild beats theoretical severity.

## Extending it (next steps)

- Real CVE feed via the NVD API instead of the sample file.
- Real posture collection (e.g. `osquery`) instead of a sample inventory.
- GenAI triage: summarize the report into an executive risk brief and suggest remediation (ties to the genAI-endpoint threat surface).
- YAML playbooks (enterprise XSOAR uses YAML; JSON here for zero-dependency portability, identical structure).

## Honest scope

This is a concept demo with sample data and mocked actions. It is not a production scanner and does not call out to real ticketing / EDR / network systems.
