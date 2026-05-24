"""
NEMESIS - Session Manager
Ejecuta comandos en Kali Linux (Docker o local) con timeout y manejo de output.
Para tools interactivas usa pexpect.
"""

import subprocess
import shlex
import os
from typing import Optional, Tuple
from rich.console import Console

console = Console()


class KaliSession:
    """Ejecuta comandos en el entorno Kali (Docker o local)."""

    def __init__(self, execution_env: str = "docker",
                 container_name: str = "nemesis-kali"):
        self.env = execution_env  # "docker" | "local"
        self.container = container_name

    def run(self, command: str, timeout: int = 300,
            stdin_input: Optional[str] = None) -> Tuple[bool, str, str]:
        """
        Ejecuta un comando y retorna (success, stdout, stderr).
        timeout en segundos.
        """
        if self.env == "docker":
            full_cmd = f"docker exec {self.container} /bin/bash -c {shlex.quote(command)}"
        else:
            full_cmd = command

        console.print(f"[dim blue]▶ {command[:100]}{'...' if len(command) > 100 else ''}[/dim blue]")

        try:
            result = subprocess.run(
                full_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=stdin_input
            )
            success = result.returncode == 0
            return success, result.stdout, result.stderr

        except subprocess.TimeoutExpired:
            console.print(f"[yellow]⏱ Timeout ({timeout}s) para: {command[:60]}[/yellow]")
            return False, "", f"TIMEOUT after {timeout}s"

        except Exception as e:
            return False, "", str(e)

    def run_nmap(self, target: str, flags: str = "-sV -sC -T4 --open",
                 port_range: str = "1-10000", timeout: int = 600) -> Tuple[bool, str, str]:
        """Ejecuta nmap con output XML para parseo fácil."""
        xml_output = f"/tmp/nmap_{target.replace('/', '_').replace('.', '_')}.xml"
        cmd = f"nmap {flags} -p {port_range} -oX {xml_output} {target}"
        success, stdout, stderr = self.run(cmd, timeout=timeout)

        # También jalamos el XML si existe
        if success and self.env == "docker":
            _, xml_content, _ = self.run(f"cat {xml_output}")
        else:
            xml_content = ""

        return success, stdout + "\n" + xml_content, stderr

    def run_nikto(self, target: str, port: int = 80,
                  timeout: int = 300) -> Tuple[bool, str, str]:
        """Escaneo de vulnerabilidades web con nikto."""
        cmd = f"nikto -h {target} -p {port} -Format txt -nointeractive"
        return self.run(cmd, timeout=timeout)

    def run_gobuster(self, target: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt",
                     port: int = 80, timeout: int = 300) -> Tuple[bool, str, str]:
        """Enumeración de directorios web."""
        protocol = "https" if port == 443 else "http"
        cmd = f"gobuster dir -u {protocol}://{target}:{port} -w {wordlist} -t 30 -q"
        return self.run(cmd, timeout=timeout)

    def run_enum4linux(self, target: str, timeout: int = 180) -> Tuple[bool, str, str]:
        """Enumeración SMB/Samba."""
        cmd = f"enum4linux -a {target}"
        return self.run(cmd, timeout=timeout)

    def run_nuclei(self, target: str, severity: str = "medium,high,critical",
                   timeout: int = 300) -> Tuple[bool, str, str]:
        """Escaneo de vulnerabilidades con nuclei."""
        cmd = f"nuclei -u {target} -severity {severity} -silent -no-color"
        return self.run(cmd, timeout=timeout)

    def check_kali_available(self) -> bool:
        """Verifica que el entorno Kali esté disponible."""
        if self.env == "docker":
            success, stdout, _ = self.run("whoami")
            if success:
                console.print(f"[green]✅ Kali Docker disponible (usuario: {stdout.strip()})[/green]")
                return True
            else:
                console.print("[red]❌ Contenedor Kali no disponible. ¿Levantaste docker-compose?[/red]")
                return False
        else:
            # Verificar que nmap esté disponible localmente
            success, _, _ = self.run("which nmap")
            return success
