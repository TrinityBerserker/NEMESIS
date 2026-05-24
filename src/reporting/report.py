"""
NEMESIS - Report Generator
Genera reportes HTML profesionales del engagement.
"""

from datetime import datetime
from pathlib import Path
from jinja2 import Template
from rich.console import Console

console = Console()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>NEMESIS — Reporte de Engagement</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }
  .header { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 40px;
            border-bottom: 2px solid #30363d; }
  .header h1 { color: #58a6ff; font-size: 2rem; letter-spacing: 4px; }
  .header .meta { color: #8b949e; margin-top: 10px; font-size: 0.9rem; }
  .container { max-width: 1100px; margin: 0 auto; padding: 30px; }
  .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 30px 0; }
  .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
               padding: 20px; text-align: center; }
  .stat-card .number { font-size: 2.5rem; font-weight: bold; }
  .stat-card .label { color: #8b949e; font-size: 0.8rem; margin-top: 5px; }
  .critical .number { color: #f85149; }
  .high .number { color: #e3b341; }
  .medium .number { color: #f0883e; }
  .low .number { color: #3fb950; }

  .findings { margin-top: 30px; }
  .finding { background: #161b22; border: 1px solid #30363d; border-radius: 8px;
             margin-bottom: 20px; overflow: hidden; }
  .finding-header { padding: 15px 20px; display: flex; align-items: center; gap: 15px; }
  .severity-badge { padding: 4px 12px; border-radius: 20px; font-size: 0.75rem;
                    font-weight: bold; letter-spacing: 1px; }
  .badge-CRITICAL { background: #f851491a; color: #f85149; border: 1px solid #f85149; }
  .badge-HIGH { background: #e3b3411a; color: #e3b341; border: 1px solid #e3b341; }
  .badge-MEDIUM { background: #f0883e1a; color: #f0883e; border: 1px solid #f0883e; }
  .badge-LOW { background: #3fb9501a; color: #3fb950; border: 1px solid #3fb950; }
  .badge-INFO { background: #58a6ff1a; color: #58a6ff; border: 1px solid #58a6ff; }
  .finding-title { font-weight: 600; font-size: 1rem; }
  .finding-target { color: #8b949e; font-size: 0.85rem; margin-left: auto; }
  .finding-body { padding: 15px 20px; border-top: 1px solid #30363d; }
  .finding-body p { color: #c9d1d9; line-height: 1.6; margin-bottom: 10px; }
  .evidence { background: #0d1117; border: 1px solid #30363d; border-radius: 4px;
              padding: 12px; font-family: monospace; font-size: 0.8rem;
              color: #8b949e; overflow-x: auto; white-space: pre-wrap; }

  .footer { text-align: center; padding: 30px; color: #8b949e; font-size: 0.8rem;
            border-top: 1px solid #30363d; margin-top: 40px; }
  h2 { color: #58a6ff; margin-bottom: 20px; font-size: 1.2rem; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
</style>
</head>
<body>
<div class="header">
  <div style="max-width:1100px; margin:0 auto;">
    <h1>⚔ NEMESIS</h1>
    <div class="meta">
      <strong>{{ engagement }}</strong> &nbsp;|&nbsp;
      Operador: {{ operator }} &nbsp;|&nbsp;
      Fecha: {{ date }} &nbsp;|&nbsp;
      Organización: {{ organization }}
    </div>
    <div class="meta" style="margin-top:8px;">
      Targets: {{ targets | join(', ') }}
    </div>
  </div>
</div>

<div class="container">
  <div class="summary-grid">
    <div class="stat-card critical">
      <div class="number">{{ counts.CRITICAL }}</div>
      <div class="label">CRITICAL</div>
    </div>
    <div class="stat-card high">
      <div class="number">{{ counts.HIGH }}</div>
      <div class="label">HIGH</div>
    </div>
    <div class="stat-card medium">
      <div class="number">{{ counts.MEDIUM }}</div>
      <div class="label">MEDIUM</div>
    </div>
    <div class="stat-card low">
      <div class="number">{{ counts.LOW }}</div>
      <div class="label">LOW / INFO</div>
    </div>
  </div>

  <div class="findings">
    <h2>📋 Hallazgos</h2>
    {% if findings %}
      {% for f in findings %}
      <div class="finding">
        <div class="finding-header">
          <span class="severity-badge badge-{{ f.severity }}">{{ f.severity }}</span>
          <span class="finding-title">{{ f.title }}</span>
          <span class="finding-target">{{ f.target }}</span>
        </div>
        <div class="finding-body">
          <p>{{ f.description }}</p>
          {% if f.evidence %}
          <div class="evidence">{{ f.evidence }}</div>
          {% endif %}
        </div>
      </div>
      {% endfor %}
    {% else %}
      <p style="color:#8b949e; text-align:center; padding:40px;">No se registraron hallazgos.</p>
    {% endif %}
  </div>
</div>

<div class="footer">
  Generado por NEMESIS &nbsp;|&nbsp; {{ date }} &nbsp;|&nbsp; USO INTERNO AUTORIZADO
</div>
</body>
</html>
"""


class ReportGenerator:
    def __init__(self, config: dict):
        self.config = config
        self.report_dir = Path(config.get("reporting", {}).get("report_dir", "./reports"))
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, findings: list, targets: list) -> str:
        """Genera reporte HTML y retorna la ruta del archivo."""
        engagement = self.config.get("engagement", {})
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "INFO").upper()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["LOW"] += 1  # LOW/INFO juntos

        template = Template(HTML_TEMPLATE)
        html = template.render(
            engagement=engagement.get("name", "Engagement"),
            operator=engagement.get("operator", "Unknown"),
            organization=engagement.get("organization", ""),
            date=datetime.now().strftime("%Y-%m-%d %H:%M"),
            targets=targets,
            findings=findings,
            counts=counts
        )

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.report_dir / f"nemesis_report_{timestamp}.html"

        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)

        console.print(f"\n[bold green]📄 Reporte generado: {report_path}[/bold green]")
        return str(report_path)
