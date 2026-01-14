
import os, sys, time, json, hashlib, zipfile, subprocess
from pathlib import Path

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    ts = int(time.time())
    outdir = Path(f"compliance_pack_{ts}")
    outdir.mkdir(parents=True, exist_ok=True)

    p = subprocess.run([sys.executable, "tools/conformance_report.py"], capture_output=True, text=True)
    (outdir/"conformance_result.txt").write_text(p.stdout + "\n" + p.stderr, encoding="utf-8")

    if Path("artifact_log.json").exists():
        p2 = subprocess.run([sys.executable, "tools/verify_artifact_log_chain.py", "artifact_log.json"], capture_output=True, text=True)
        (outdir/"artifact_log_chain_check.txt").write_text(p2.stdout + "\n" + p2.stderr, encoding="utf-8")
        (outdir/"artifact_log.json").write_bytes(Path("artifact_log.json").read_bytes())

    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        pdf_path = outdir/"BinaryIF_Compliance_Report.pdf"
        c = canvas.Canvas(str(pdf_path), pagesize=letter)
        y = letter[1] - 72
        c.setFont("Times-Roman", 14)
        c.drawString(72, y, "BinaryIF Compliance Report")
        y -= 24
        c.setFont("Times-Roman", 11)
        c.drawString(72, y, f"Generated: {time.ctime(ts)}")
        y -= 18
        first = (outdir/"conformance_result.txt").read_text(encoding="utf-8").splitlines()[:1]
        if first:
            c.drawString(72, y, "Conformance: " + first[0].strip())
        c.showPage()
        c.save()
    except Exception as e:
        (outdir/"pdf_error.txt").write_text(str(e), encoding="utf-8")

    manifest = {}
    for pth in outdir.rglob("*"):
        if pth.is_file():
            manifest[pth.name] = sha256_file(pth)
    (outdir/"manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    zip_path = Path(f"{outdir}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for pth in outdir.rglob("*"):
            if pth.is_file():
                z.write(pth, arcname=f"{outdir.name}/{pth.name}")
    print(str(zip_path))

if __name__ == "__main__":
    main()
