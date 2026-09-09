"""Render the current three-page brief; preserve prior PDF files."""
from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
from xml.sax.saxutils import escape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import SimpleDocTemplate, Paragraph, PageBreak
from pypdf import PdfReader


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--font", type=Path, default=Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts/msyh.ttc")
    args = p.parse_args()
    assert not args.output.exists() and not args.output.with_suffix(".json").exists()
    raw = args.source.read_bytes()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    pdfmetrics.registerFont(TTFont("BodyCN", str(args.font), subfontIndex=0))
    styles = {
        "title": ParagraphStyle("title", fontName="BodyCN", fontSize=19, leading=27,
                                textColor=colors.HexColor("#102D3A"), spaceAfter=14),
        "heading": ParagraphStyle("heading", fontName="BodyCN", fontSize=12, leading=19,
                                  textColor=colors.HexColor("#087E8B"), spaceBefore=10, spaceAfter=6, keepWithNext=True),
        "body": ParagraphStyle("body", fontName="BodyCN", fontSize=9.2, leading=15.3,
                               textColor=colors.HexColor("#293D47"), spaceAfter=8, wordWrap="CJK"),
    }

    def page(canvas, doc):
        width, height = A4
        canvas.saveState()
        canvas.setFillColor(colors.HexColor("#087E8B"))
        canvas.rect(42, height - 34, 28, 4, fill=1, stroke=0)
        canvas.setFont("BodyCN", 8)
        canvas.setFillColor(colors.HexColor("#617782"))
        canvas.drawString(79, height - 34, "VULNGYM / T2 DELIVERY BRIEF / v3")
        canvas.setStrokeColor(colors.HexColor("#DCE5E9"))
        canvas.line(42, 40, width - 42, 40)
        canvas.drawString(42, 25, "2026-09-10 | 工程候选交付，质量未全部通过")
        canvas.drawRightString(width - 42, 25, f"{doc.page} / 3")
        canvas.restoreState()

    story = []
    for line in raw.decode("utf-8").splitlines():
        if not line.strip():
            continue
        if line == "<!-- pagebreak -->":
            story.append(PageBreak())
            continue
        kind, text = ("title", line[2:]) if line.startswith("# ") else (("heading", line[3:]) if line.startswith("## ") else ("body", line))
        story.append(Paragraph(escape(text.replace("`", "")), styles[kind]))
    SimpleDocTemplate(str(args.output), pagesize=A4, leftMargin=42, rightMargin=42,
        topMargin=59, bottomMargin=54, title="VulnGym T2 - 当前交付与质量边界", author="VulnGym project",
        pageCompression=1).build(story, onFirstPage=page, onLaterPages=page)
    reader = PdfReader(args.output)
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert len(reader.pages) == 3
    for token in ("89,577", "1/2", "4项支持", "309-330", "verify=0", "9月10日"):
        assert token in text, "expected_pdf_text_missing"
    pdf = args.output.read_bytes()
    result = {"schema": "t2.delivery-pdf.v3", "pages": 3, "text_check": True,
              "visual_check": "pending", "source_sha256": sha256(raw).hexdigest(),
              "pdf": {"bytes": len(pdf), "sha256": sha256(pdf).hexdigest()}}
    with args.output.with_suffix(".json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
