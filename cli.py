#!/usr/bin/env python3
"""
NEMESIS — Autonomous Red Team Agent
CLI principal.

Uso:
  python cli.py scan --target 192.168.1.10
  python cli.py scan --target 192.168.1.0/24
  python cli.py scan --target 192.168.1.10 --target 192.168.1.20
  python cli.py check          # verifica que Kali esté disponible
  python cli.py scope          # muestra el scope actual
"""

import os
import sys
import click
import yaml
from pathlib import Path
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

load_dotenv()

console = Console()

BANNER = """
[bold cyan]
 ███╗   ██╗███████╗███╗   ███╗███████╗███████╗██╗███████╗
 ████╗  ██║██╔════╝████╗ ████║██╔════╝██╔════╝██║██╔════╝
 ██╔██╗ ██║█████╗  ██╔████╔██║█████╗  ███████╗██║███████╗
 ██║╚██╗██║██╔══╝  ██║╚██╔╝██║██╔══╝  ╚════██║██║╚════██║
 ██║ ╚████║███████╗██║ ╚═╝ ██║███████╗███████║██║███████║
 ╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝╚══════╝
[/bold cyan]
[dim]Autonomous Red Team Agent — USO AUTORIZADO SOLAMENTE[/dim]
"""


def load_config(config_path: str = "config.yaml") -> dict:
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def build_components(config: dict):
    """Inicializa todos los componentes del agente."""
    from src.core.roe import RulesOfEngagement
    from src.core.logger import AuditLogger
    from src.core.session import KaliSession
    from src.agents.orchestrator import NemesisOrchestrator

    roe = RulesOfEngagement(config)
    logger = AuditLogger(
        log_dir=os.getenv("LOG_DIR", "./logs"),
        engagement_name=config.get("engagement", {}).get("name", "engagement")
                                  .replace(" ", "_").lower()
    )
    session = KaliSession(
        execution_env=os.getenv("EXECUTION_ENV", "docker"),
        container_name=os.getenv("KALI_CONTAINER", "nemesis-kali")
    )
    orchestrator = NemesisOrchestrator(config, roe, logger, session)

    return roe, logger, session, orchestrator


@click.group()
def cli():
    """NEMESIS — Autonomous Red Team Agent"""
    console.print(BANNER)


@cli.command()
@click.option("--target", "-t", multiple=True, required=True,
              help="IP, hostname o CIDR objetivo (puede repetirse para múltiples targets)")
@click.option("--config", "-c", default="config.yaml",
              help="Ruta al archivo de configuración")
@click.option("--confirm/--no-confirm", default=True,
              help="Pedir confirmación antes de iniciar")
def scan(target, config, confirm):
    """Ejecuta un engagement completo contra los targets especificados."""
    cfg = load_config(config)

    if confirm:
        console.print(Panel(
            f"[yellow]⚠ ADVERTENCIA[/yellow]\n\n"
            f"Vas a iniciar un engagement de Red Team contra:\n"
            f"[bold]{', '.join(target)}[/bold]\n\n"
            f"Asegúrate de tener autorización escrita.\n"
            f"Esta acción quedará registrada en los logs.",
            title="Confirmación requerida",
            border_style="yellow"
        ))
        if not click.confirm("¿Confirmas que tienes autorización para proceder?"):
            console.print("[red]Cancelado.[/red]")
            sys.exit(0)

    roe, logger, session, orchestrator = build_components(cfg)

    # Verificar Kali
    if not session.check_kali_available():
        console.print("[red]❌ Kali no disponible. Levanta el contenedor Docker primero:[/red]")
        console.print("[dim]docker-compose up -d[/dim]")
        sys.exit(1)

    orchestrator.run(list(target))


@cli.command()
@click.option("--config", "-c", default="config.yaml")
def scope(config):
    """Muestra el scope autorizado actual."""
    cfg = load_config(config)
    from src.core.roe import RulesOfEngagement
    roe = RulesOfEngagement(cfg)
    roe.print_scope()


@cli.command()
def check():
    """Verifica que el entorno Kali esté disponible."""
    from src.core.session import KaliSession
    session = KaliSession(
        execution_env=os.getenv("EXECUTION_ENV", "docker"),
        container_name=os.getenv("KALI_CONTAINER", "nemesis-kali")
    )
    available = session.check_kali_available()
    if not available:
        console.print("\n[dim]Para levantar el contenedor:[/dim]")
        console.print("[dim]  docker-compose up -d[/dim]")
        sys.exit(1)


@cli.command()
@click.option("--config", "-c", default="config.yaml")
def report(config):
    """Genera un reporte de los hallazgos en los logs."""
    cfg = load_config(config)
    from src.core.logger import AuditLogger
    from src.reporting.report import ReportGenerator

    log_dir = Path(os.getenv("LOG_DIR", "./logs"))
    log_files = list(log_dir.glob("*.jsonl"))

    if not log_files:
        console.print("[yellow]No se encontraron logs.[/yellow]")
        sys.exit(0)

    # Usar el más reciente
    latest = max(log_files, key=lambda f: f.stat().st_mtime)
    console.print(f"[cyan]Usando log: {latest}[/cyan]")

    import json
    findings = []
    targets = set()
    with open(latest) as f:
        for line in f:
            entry = json.loads(line)
            if entry.get("event") == "FINDING":
                findings.append(entry)
            if entry.get("event") == "ACTION":
                targets.add(entry.get("target", ""))

    reporter = ReportGenerator(cfg)
    reporter.generate(findings, list(targets))


if __name__ == "__main__":
    cli()
