"""
NEMESIS - Audit Logger
Registra cada acción del agente con timestamp, resultado y metadatos.
Todo queda en logs para evidencia del engagement.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional
from rich.console import Console

console = Console()


class AuditLogger:
    def __init__(self, log_dir: str = "./logs", engagement_name: str = "engagement"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = self.log_dir / f"nemesis_{engagement_name}_{timestamp}.jsonl"
        self.text_log = self.log_dir / f"nemesis_{engagement_name}_{timestamp}.log"

        # Logger de texto plano
        logging.basicConfig(
            filename=self.text_log,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s"
        )
        self.logger = logging.getLogger("nemesis")

        self._write_event("SESSION_START", {
            "engagement": engagement_name,
            "timestamp": datetime.now().isoformat()
        })

    def _write_event(self, event_type: str, data: dict):
        """Escribe un evento al log JSONL."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event": event_type,
            **data
        }
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def log_action(self, action: str, target: str, command: str,
                   output: str = "", success: bool = True,
                   findings: Optional[list] = None):
        """Registra una acción ejecutada por el agente."""
        self._write_event("ACTION", {
            "action": action,
            "target": target,
            "command": command,
            "success": success,
            "output_length": len(output),
            "findings": findings or []
        })
        self.logger.info(f"[{action}] target={target} | cmd={command[:80]}...")

        status = "✅" if success else "❌"
        console.print(f"[dim]{status} [{action}] {target}[/dim]")

    def log_finding(self, severity: str, title: str, target: str,
                    description: str, evidence: str = ""):
        """Registra un hallazgo de seguridad."""
        colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "blue"
        }
        color = colors.get(severity.lower(), "white")

        self._write_event("FINDING", {
            "severity": severity.upper(),
            "title": title,
            "target": target,
            "description": description,
            "evidence": evidence[:500]  # truncar evidencia muy larga
        })

        console.print(f"[{color}]🔍 [{severity.upper()}] {title} — {target}[/{color}]")

    def log_roe_violation(self, action: str, reason: str):
        """Registra una violación de RoE (acción bloqueada)."""
        self._write_event("ROE_VIOLATION", {
            "blocked_action": action,
            "reason": reason
        })
        console.print(f"[bold red]🚫 RoE VIOLATION: {reason}[/bold red]")
        self.logger.warning(f"ROE_VIOLATION: {reason}")

    def log_phase(self, phase: str, status: str = "START"):
        """Registra el inicio/fin de una fase del engagement."""
        self._write_event("PHASE", {"phase": phase, "status": status})
        icon = "🚀" if status == "START" else "✅"
        console.print(f"\n[bold cyan]{icon} FASE: {phase} — {status}[/bold cyan]\n")

    def get_findings(self) -> list:
        """Retorna todos los hallazgos del engagement actual."""
        findings = []
        with open(self.log_file, "r") as f:
            for line in f:
                entry = json.loads(line)
                if entry.get("event") == "FINDING":
                    findings.append(entry)
        return findings
