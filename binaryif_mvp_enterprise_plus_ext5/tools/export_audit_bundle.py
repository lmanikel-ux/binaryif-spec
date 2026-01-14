
"""Export an insurer/auditor bundle:
- trust store snapshot
- revocation list
- ruleset
- latest artifact log (full)
- last permit artifact (if present in artifacts/permit.json)
- conformance PASS output (if available)
Produces: audit_bundle_<epoch>.zip
"""
import os, json, zipfile, time, subprocess, sys
from pathlib import Path

def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    ts = int(time.time())
    out = Path(f"audit_bundle_{ts}.zip")
    items = [
        ("trust/trust_store.json", "trust_store.json"),
        ("trust/revocation_list.json", "revocation_list.json"),
        ("rules/wire_ruleset.json", "ruleset.json"),
    ]

    # Pull artifact log from running service if available, else from local db export endpoint is not accessible.
    # Here we export a placeholder file if not provided.
    # Recommended: curl http://localhost:8000/artifact_log > artifact_log.json then run this.
    if Path("artifact_log.json").exists():
        items.append(("artifact_log.json", "artifact_log.json"))

    if Path("artifacts/permit.json").exists():
        items.append(("artifacts/permit.json", "permit.json"))

    # Capture conformance result
    conf_path = Path("conformance_result.txt")
    try:
        p = subprocess.run([sys.executable, "tools/conformance_report.py"], capture_output=True, text=True)
        conf_path.write_text(p.stdout + "\n" + p.stderr, encoding="utf-8")
        items.append((str(conf_path), "conformance_result.txt"))
    except Exception:
        pass

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for src, arc in items:
            if Path(src).exists():
                z.write(src, arcname=arc)

    print(str(out))

if __name__ == "__main__":
    main()
