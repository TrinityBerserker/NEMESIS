"""
NEMESIS - Recon Agent
Maneja el reconocimiento inicial: nmap, parseo de puertos,
detección de servicios y OS.
"""

import re
from typing import Tuple, List, Dict, Optional
from dataclasses import dataclass
from rich.console import Console
from rich.table import Table

console = Console()


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str
    version: str
    extra_info: str = ""


@dataclass
class Host:
    ip: str
    hostname: Optional[str]
    os_guess: Optional[str]
    ports: List[Port]
    is_up: bool


class ReconAgent:
    def __init__(self, session, roe, logger):
        self.session = session
        self.roe = roe
        self.logger = logger

    def run_nmap(self, target: str,
                 flags: str = "-sV -sC -T4 --open",
                 port_range: str = "1-10000") -> Tuple[bool, str, str]:
        """Ejecuta nmap y retorna output raw."""
        success, stdout, stderr = self.session.run_nmap(
            target, flags=flags, port_range=port_range
        )
        if success:
            hosts = self.parse_nmap_output(stdout)
            self._print_hosts_table(hosts)
        return success, stdout, stderr

    def parse_nmap_output(self, nmap_output: str) -> List[Host]:
        """Parsea output de nmap en texto plano."""
        hosts = []
        current_host = None
        current_ports = []

        for line in nmap_output.split('\n'):
            line = line.strip()

            # Detectar nuevo host
            ip_match = re.match(r'Nmap scan report for (.+)', line)
            if ip_match:
                if current_host:
                    current_host.ports = current_ports
                    hosts.append(current_host)

                host_str = ip_match.group(1)
                # Puede ser "hostname (ip)" o solo "ip"
                hostname_ip = re.match(r'(.+) \((\d+\.\d+\.\d+\.\d+)\)', host_str)
                if hostname_ip:
                    hostname = hostname_ip.group(1)
                    ip = hostname_ip.group(2)
                else:
                    hostname = None
                    ip = host_str

                current_host = Host(
                    ip=ip, hostname=hostname,
                    os_guess=None, ports=[], is_up=True
                )
                current_ports = []

            # Detectar puertos abiertos
            port_match = re.match(
                r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)', line
            )
            if port_match and current_host:
                port = Port(
                    number=int(port_match.group(1)),
                    protocol=port_match.group(2),
                    state=port_match.group(3),
                    service=port_match.group(4),
                    version=port_match.group(5).strip()
                )
                current_ports.append(port)

            # Detectar OS
            os_match = re.match(r'OS details: (.+)', line)
            if os_match and current_host:
                current_host.os_guess = os_match.group(1)

        # Agregar último host
        if current_host:
            current_host.ports = current_ports
            hosts.append(current_host)

        return hosts

    def _print_hosts_table(self, hosts: List[Host]):
        """Imprime tabla de resultados en consola."""
        for host in hosts:
            if not host.ports:
                continue

            table = Table(
                title=f"🖥 {host.ip}" + (f" ({host.hostname})" if host.hostname else "") +
                      (f" — {host.os_guess}" if host.os_guess else ""),
                border_style="cyan"
            )
            table.add_column("Puerto", style="cyan", width=10)
            table.add_column("Proto", width=6)
            table.add_column("Estado", width=10)
            table.add_column("Servicio", style="green", width=15)
            table.add_column("Versión", style="yellow")

            for port in host.ports:
                state_color = "green" if port.state == "open" else "yellow"
                table.add_row(
                    str(port.number),
                    port.protocol,
                    f"[{state_color}]{port.state}[/{state_color}]",
                    port.service,
                    port.version
                )

            console.print(table)

    def get_interesting_ports(self, hosts: List[Host]) -> Dict[str, List[Port]]:
        """
        Retorna puertos interesantes agrupados por categoría.
        Útil para que el orquestador decida qué analizar a fondo.
        """
        interesting = {
            "web": [],
            "smb": [],
            "rdp": [],
            "ssh": [],
            "database": [],
            "voip": [],
            "management": []
        }

        web_ports = {80, 443, 8080, 8443, 8000, 3000, 5000}
        smb_ports = {139, 445}
        db_ports = {1433, 3306, 5432, 1521, 27017, 6379}
        voip_ports = {5060, 5061, 4569, 2000}
        mgmt_ports = {161, 162, 623, 8888, 9090}

        for host in hosts:
            for port in host.ports:
                if port.state != "open":
                    continue
                n = port.number
                if n in web_ports or "http" in port.service.lower():
                    interesting["web"].append((host.ip, port))
                elif n in smb_ports:
                    interesting["smb"].append((host.ip, port))
                elif n == 3389:
                    interesting["rdp"].append((host.ip, port))
                elif n == 22:
                    interesting["ssh"].append((host.ip, port))
                elif n in db_ports:
                    interesting["database"].append((host.ip, port))
                elif n in voip_ports:
                    interesting["voip"].append((host.ip, port))
                elif n in mgmt_ports:
                    interesting["management"].append((host.ip, port))

        return interesting

    def summarize_for_llm(self, hosts: List[Host]) -> str:
        """Genera un resumen textual para enviar al LLM."""
        if not hosts:
            return "No se encontraron hosts activos."

        lines = []
        for host in hosts:
            lines.append(f"\nHost: {host.ip}" +
                        (f" ({host.hostname})" if host.hostname else "") +
                        (f" — OS: {host.os_guess}" if host.os_guess else ""))

            if not host.ports:
                lines.append("  Sin puertos abiertos detectados")
            else:
                for p in host.ports:
                    lines.append(f"  {p.number}/{p.protocol} {p.state} — {p.service} {p.version}")

        return "\n".join(lines)
