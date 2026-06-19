"""Workforce Sentinel: mini endpoint posture + vulnerability + SOAR demo."""

import argparse
import glob
import json
import os

from sentinel import posture, vulns, engine, hardening

ROOT = os.path.dirname(os.path.abspath(__file__))
SEV_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def load_json(path):
    with open(path) as f:
        return json.load(f)


def load_playbooks(folder):
    return [load_json(p) for p in sorted(glob.glob(os.path.join(folder, "*.json")))]


def risk_by_device(findings):
    scores = {}
    for f in findings:
        scores[f["device_id"]] = scores.get(f["device_id"], 0) + SEV_WEIGHT.get(f["severity"], 0)
    return dict(sorted(scores.items(), key=lambda kv: kv[1], reverse=True))


def main():
    ap = argparse.ArgumentParser(description="Workforce Sentinel: endpoint posture + vuln + SOAR demo")
    ap.add_argument("--inventory", default=os.path.join(ROOT, "data", "inventory.sample.json"))
    ap.add_argument("--cve", default=os.path.join(ROOT, "data", "cve_feed.sample.json"))
    ap.add_argument("--playbooks", default=os.path.join(ROOT, "playbooks"))
    ap.add_argument("--report", default=os.path.join(ROOT, "report.json"))
    args = ap.parse_args()

    inventory = load_json(args.inventory)
    cve_feed = load_json(args.cve)
    playbooks = load_playbooks(args.playbooks)

    posture_findings = posture.scan(inventory)
    hardening_findings = hardening.scan(inventory)
    vuln_findings = vulns.scan(inventory, cve_feed)
    findings = posture_findings + hardening_findings + vuln_findings
    actions = engine.run(findings, playbooks)
    risk = risk_by_device(findings)

    print("=" * 66)
    print(" WORKFORCE SENTINEL  .  endpoint posture + vuln + SOAR demo")
    print("=" * 66)
    print(f" Devices scanned : {len(inventory)}")
    print(f" Playbooks loaded: {len(playbooks)}")
    print(f" Findings        : {len(findings)} ({len(posture_findings)} posture, {len(hardening_findings)} CIS hardening, {len(vuln_findings)} vuln)")
    print(f" Playbook actions: {len(actions)}")

    print("\n RISK BY DEVICE (severity-weighted)")
    for dev, score in risk.items():
        print(f"   {dev:<11} score {score}")

    print("\n FINDINGS (highest severity first)")
    for f in sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"], 9)):
        tag = "KEV" if f.get("kev") else "   "
        print(f"   [{f['severity'].upper():<8}] {tag}  {f['device_id']:<11} {f['description']}")

    print("\n AUTOMATED PLAYBOOK ACTIONS (SOAR)")
    for a in actions:
        act = a["action"]
        extra = " ".join(f"{k}={v}" for k, v in act.items() if k != "do")
        print(f"   {a['device_id']:<11} {act.get('do'):<22} {extra:<34} <- {a['playbook']}")

    with open(args.report, "w") as f:
        json.dump({"findings": findings, "actions": actions, "risk": risk}, f, indent=2)
    print(f"\n Full machine-readable report: {args.report}")


if __name__ == "__main__":
    main()
