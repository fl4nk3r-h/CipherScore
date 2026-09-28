"""Jinja2 -> HTML -> WeasyPrint PDF (repo.md §4; mvp.md §3.6).

| Executive Report (2 pages) | Management | Security Score gauge, grade, top 5 risks in plain language, Threat Matrix, compliance badges (RFC 8221/8247, NIST, CNSA), recommended actions ranked by impact |
| Technical Report (8-20 pages) | Analysts | Per-SA parameter table with Observed/Inferred/Unknown tags and confidence, IKE exchange timeline, rekey/lifetime chart, traffic-type breakdown with conformal sets, all findings with evidence (packet numbers, fields), remediation config snippets for strongSwan, model card and limitations |
"""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML

TEMPLATES = Path(__file__).parent / "templates"


def render_html(context: dict, template: str) -> str:
    env = Environment(loader=FileSystemLoader(TEMPLATES))
    return env.get_template(template).render(**context)


def to_pdf(html: str, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html, base_url=str(TEMPLATES)).write_pdf(out_path)
    return out_path


def all_reports(context: dict, out_dir: Path) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    exec_pdf = to_pdf(render_html(context, "executive.html.j2"),
                      out_dir / "executive.pdf")
    tech_pdf = to_pdf(render_html(context, "technical.html.j2"),
                      out_dir / "technical.pdf")
    return {"executive": exec_pdf, "technical": tech_pdf}
