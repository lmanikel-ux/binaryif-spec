
import os, sys, time, json, zipfile, subprocess
from pathlib import Path
from app.util import canonicalize, sha256_hex

def load_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))

def snapshot(src: Path, outdir: Path, name: str) -> str:
    data = load_json(src)
    h = sha256_hex(canonicalize(data))
    out = outdir / f"{name}_{h}.json"
    out.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return h

def main():
    ts = int(time.time())
    outdir = Path(f"insurer_packet_{ts}")
    outdir.mkdir(parents=True, exist_ok=True)

    conf = subprocess.run([sys.executable, "tools/conformance_report.py"], capture_output=True, text=True)
    (outdir/"conformance.txt").write_text(conf.stdout + "\n" + conf.stderr, encoding="utf-8")

    comp = subprocess.run([sys.executable, "tools/generate_compliance_pack.py"], capture_output=True, text=True)
    (outdir/"compliance_pack_path.txt").write_text(comp.stdout + "\n" + comp.stderr, encoding="utf-8")

    trust_hash = snapshot(Path("trust/trust_store.json"), outdir, "trust_store")
    rev_hash = snapshot(Path("trust/revocation_list.json"), outdir, "revocation_list")
    ruleset_hash = snapshot(Path("rules/wire_ruleset.json"), outdir, "ruleset")

    rider = subprocess.run([sys.executable, "tools/generate_policy_rider.py", "--threshold", "250000", "--currency", "USD", "--ttl", "300", "--action", "wire_transfer"], capture_output=True, text=True)
    (outdir/"policy_rider.txt").write_text(rider.stdout + "\n" + rider.stderr, encoding="utf-8")

    (outdir/"artifact_log_instructions.txt").write_text(
        "Export artifact log:\n  curl http://127.0.0.1:8000/artifact_log > artifact_log.json\nVerify chain:\n  python tools/verify_artifact_log_chain.py artifact_log.json\n",
        encoding="utf-8"
    )

    index = {
        "generated_at_epoch": ts,
        "trust_store_hash": trust_hash,
        "revocation_list_hash": rev_hash,
        "ruleset_hash": ruleset_hash,
        "notes": "Attach permit.json for executed transfer and artifact_log.json export for full audit chain."
    }
    (outdir/"index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")

    zip_path = Path(f"{outdir}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in outdir.rglob("*"):
            if p.is_file():
                z.write(p, arcname=f"{outdir.name}/{p.name}")
    print(str(zip_path))

if __name__ == "__main__":
    main()
