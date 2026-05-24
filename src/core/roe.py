"""
NEMESIS - Rules of Engagement (RoE)
Valida que cualquier acción esté dentro del scope autorizado.
Nada se ejecuta sin pasar por aquí primero.
"""

import ipaddress
from datetime import datetime
from typing import Union
from rich.console import Console
from rich.panel import Panel

console = Console()


class RoEViolation(Exception):
    """Se lanza cuando una acción viola las Rules of Engagement."""
    pass


class RulesOfEngagement:
    def __init__(self, config: dict):
        roe = config.get("roe", {})

        self.authorized_networks = [
            ipaddress.ip_network(net, strict=False)
            for net in roe.get("authorized_targets", [])
        ]
        self.excluded_ips = set(roe.get("excluded_targets", []))
        self.excluded_ports = set(roe.get("excluded_ports", []))
        self.allowed_hours = roe.get("allowed_hours", {})
        self.enforce_hours = self.allowed_hours.get("enforce", False)
        self.kill_switch_strings = [
            s.lower() for s in roe.get("kill_switch_strings", [])
        ]

    def validate_target(self, target: str) -> bool:
        """Valida que un IP/host esté dentro del scope autorizado."""
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            # Es un hostname, no un IP — permitir con advertencia
            console.print(f"[yellow]⚠ Hostname '{target}' no validado como IP — verifica el scope[/yellow]")
            return True

        # Verificar exclusiones primero
        if str(ip) in self.excluded_ips:
            raise RoEViolation(f"❌ IP {ip} está en la lista de EXCLUSIÓN. Acción bloqueada.")

        # Verificar que esté en redes autorizadas
        in_scope = any(ip in net for net in self.authorized_networks)
        if not in_scope:
            raise RoEViolation(
                f"❌ IP {ip} FUERA DE SCOPE. Redes autorizadas: "
                f"{[str(n) for n in self.authorized_networks]}"
            )

        return True

    def validate_port(self, port: int) -> bool:
        """Valida que un puerto no esté excluido."""
        if port in self.excluded_ports:
            raise RoEViolation(f"❌ Puerto {port} está excluido por RoE.")
        return True

    def validate_hours(self) -> bool:
        """Valida que estemos dentro del horario permitido."""
        if not self.enforce_hours:
            return True

        now = datetime.now().strftime("%H:%M")
        start = self.allowed_hours.get("start", "00:00")
        end = self.allowed_hours.get("end", "23:59")

        if start <= now <= end:
            return True

        raise RoEViolation(
            f"❌ Fuera del horario permitido ({start} - {end}). Hora actual: {now}"
        )

    def check_kill_switch(self, text: str) -> bool:
        """Revisa si el output contiene strings que deben detener el agente."""
        text_lower = text.lower()
        for trigger in self.kill_switch_strings:
            if trigger in text_lower:
                raise RoEViolation(
                    f"🛑 KILL SWITCH activado: se detectó '{trigger}' en el output. "
                    f"Deteniendo todas las operaciones."
                )
        return True

    def validate_all(self, target: str, port: int = None) -> bool:
        """Validación completa antes de cualquier acción."""
        self.validate_hours()
        self.validate_target(target)
        if port:
            self.validate_port(port)
        return True

    def print_scope(self):
        """Imprime el scope actual en consola."""
        networks = "\n".join(f"  ✅ {n}" for n in self.authorized_networks)
        excluded = "\n".join(f"  ❌ {ip}" for ip in self.excluded_ips)

        console.print(Panel(
            f"[bold green]Redes autorizadas:[/bold green]\n{networks}\n\n"
            f"[bold red]Excluidos:[/bold red]\n{excluded}",
            title="[bold cyan]📋 Rules of Engagement[/bold cyan]",
            border_style="cyan"
        ))
