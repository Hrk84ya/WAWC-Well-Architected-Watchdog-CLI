"""HTML and PDF report generation (Pro feature)."""

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from wawc.core.findings import ScanResult, Severity
from wawc.pro.license import require_pro
from wawc.wa.mapping import get_pillar_summary, group_findings_by_pillar

logger = logging.getLogger(__name__)


@require_pro
def generate_html_report(result: ScanResult, output_path: str) -> None:
    """Generate HTML report from scan results."""
    template_dir = Path(__file__).parent.parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    template = env.get_template("report.html")

    # Prepare data
    pillar_summary = get_pillar_summary(result)
    pillar_findings = group_findings_by_pillar(result)

    severity_counts = {
        "high": sum(1 for f in result.findings if f.severity == Severity.HIGH),
        "medium": sum(1 for f in result.findings if f.severity == Severity.MEDIUM),
        "low": sum(1 for f in result.findings if f.severity == Severity.LOW),
    }

    html_content = template.render(
        result=result,
        pillar_summary=pillar_summary,
        pillar_findings=pillar_findings,
        severity_counts=severity_counts,
    )

    Path(output_path).write_text(html_content)
    logger.info(f"HTML report generated: {output_path}")
    print(f"✓ HTML report saved to: {output_path}")


@require_pro
def generate_pdf_report(html_path: str, pdf_path: str) -> None:
    """Generate PDF from HTML report using Playwright."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(f"file://{Path(html_path).absolute()}")
            page.pdf(path=pdf_path, format="A4")
            browser.close()

        logger.info(f"PDF report generated: {pdf_path}")
        print(f"✓ PDF report saved to: {pdf_path}")

    except ImportError:
        print("⚠ Playwright not installed. Install with: pip install playwright")
        print("  Then run: playwright install chromium")
    except Exception as e:
        logger.error(f"Error generating PDF: {e}")
        print(f"⚠ Error generating PDF: {e}")
