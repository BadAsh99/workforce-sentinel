"""GenAI triage: turn the findings report into an executive risk brief.

Step 1 (DAEDALUS): build the context we will feed the LLM. Pure Python, no API.
"""


def build_brief_context(report):
    # YOUR TASK: return a short TEXT summary of `report` that an LLM could brief on.
    # It must include:
    #   1. total number of findings
    #   2. a count per severity (critical / high / medium / low)
    #   3. the top 3 devices by risk score
    #   4. the list of CRITICAL finding descriptions
    #
    # Hints (not the answer):
    #   report["findings"] -> list of dicts, each has "severity", "description", "device_id"
    #   report["risk"]     -> dict {device_id: score}, already sorted high -> low
    #   counting: a plain dict, or collections.Counter
    #   top 3 devices: list(report["risk"].items())[:3]
    #   critical only: [f for f in report["findings"] if f["severity"] == "critical"]
    #   build the string with f-strings and "\n".join(...)
    return "TODO: build the context"  # <- replace this with your real summary


if __name__ == "__main__":
    import json
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "report.json")
    print(build_brief_context(json.load(open(path))))
