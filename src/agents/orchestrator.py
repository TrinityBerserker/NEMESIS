"""
NEMESIS - Orchestrator Agent
El cerebro. Usa LangGraph para decidir qué herramienta ejecutar
basándose en los resultados anteriores.
"""

import os
from typing import TypedDict, Annotated, List, Optional
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_anthropic import ChatAnthropic
from langchain_openai import ChatOpenAI
from rich.console import Console
from rich.panel import Panel

from src.core.roe import RulesOfEngagement, RoEViolation
from src.core.logger import AuditLogger
from src.core.session import KaliSession
from src.agents.recon import ReconAgent

console = Console()

SYSTEM_PROMPT = """Eres NEMESIS, un agente autónomo de Red Team para auditorías de seguridad internas autorizadas.

Tu trabajo es:
1. Analizar los resultados de reconocimiento
2. Identificar vulnerabilidades y superficies de ataque
3. Decidir qué herramienta ejecutar a continuación
4. Documentar hallazgos con severidad (CRITICAL/HIGH/MEDIUM/LOW/INFO)

REGLAS ESTRICTAS:
- Solo operas contra targets en el scope autorizado
- Documentas TODO
- Si encuentras algo crítico, lo reportas inmediatamente
- Operas de forma metódica: recon → enumeration → análisis → reporte
- Nunca ejecutas acciones destructivas

Cuando quieras ejecutar una herramienta, responde con este formato JSON exacto:
{
  "action": "run_tool",
  "tool": "nmap|nikto|gobuster|enum4linux|nuclei",
  "target": "ip_o_host",
  "params": {},
  "reasoning": "por qué ejecutas esto"
}

Cuando hayas terminado el análisis de un target, responde con:
{
  "action": "finding",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "title": "título del hallazgo",
  "description": "descripción detallada",
  "evidence": "fragmento del output relevante"
}

Cuando hayas completado el engagement:
{
  "action": "complete",
  "summary": "resumen del engagement"
}
"""


class NemesisState(TypedDict):
    messages: Annotated[list, add_messages]
    targets: List[str]
    current_target: Optional[str]
    phase: str
    findings: List[dict]
    completed: bool


class NemesisOrchestrator:
    def __init__(self, config: dict, roe: RulesOfEngagement,
                 logger: AuditLogger, session: KaliSession):
        self.config = config
        self.roe = roe
        self.logger = logger
        self.session = session
        self.recon = ReconAgent(session, roe, logger)

        # Inicializar LLM según configuración
        provider = os.getenv("LLM_PROVIDER", "anthropic")
        if provider == "anthropic":
            self.llm = ChatAnthropic(
                model=os.getenv("LLM_MODEL", "claude-opus-4-5"),
                temperature=0
            )
        else:
            self.llm = ChatOpenAI(
                model=os.getenv("LLM_MODEL", "gpt-4o"),
                temperature=0
            )

        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:
        """Construye el grafo de estados del agente."""
        graph = StateGraph(NemesisState)

        graph.add_node("plan", self._plan_node)
        graph.add_node("execute", self._execute_node)
        graph.add_node("analyze", self._analyze_node)
        graph.add_node("report", self._report_node)

        graph.set_entry_point("plan")
        graph.add_edge("plan", "execute")
        graph.add_edge("execute", "analyze")
        graph.add_conditional_edges(
            "analyze",
            self._should_continue,
            {
                "continue": "plan",
                "report": "report",
                "end": END
            }
        )
        graph.add_edge("report", END)

        return graph.compile()

    def _plan_node(self, state: NemesisState) -> NemesisState:
        """El LLM decide qué hacer a continuación."""
        self.logger.log_phase("PLANNING")

        context = f"""
Targets autorizados: {state['targets']}
Target actual: {state.get('current_target', 'ninguno')}
Fase actual: {state['phase']}
Hallazgos hasta ahora: {len(state['findings'])}

Decide la siguiente acción de reconocimiento.
"""
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=context)
        ] + state["messages"][-10:]  # últimos 10 mensajes para contexto

        response = self.llm.invoke(messages)

        return {
            **state,
            "messages": state["messages"] + [response]
        }

    def _execute_node(self, state: NemesisState) -> NemesisState:
        """Ejecuta la acción decidida por el LLM."""
        import json
        import re

        last_msg = state["messages"][-1]
        content = last_msg.content if hasattr(last_msg, 'content') else str(last_msg)

        # Extraer JSON de la respuesta
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        if not json_match:
            return state

        try:
            action_data = json.loads(json_match.group())
        except json.JSONDecodeError:
            return state

        action = action_data.get("action")
        tool = action_data.get("tool")
        target = action_data.get("target", state.get("current_target"))

        # Validar contra RoE antes de ejecutar
        try:
            self.roe.validate_all(target)
        except RoEViolation as e:
            self.logger.log_roe_violation(f"{tool}:{target}", str(e))
            return {
                **state,
                "messages": state["messages"] + [
                    HumanMessage(content=f"RoE VIOLATION — acción bloqueada: {e}")
                ]
            }

        result = ""

        if action == "run_tool":
            reasoning = action_data.get("reasoning", "")
            console.print(Panel(
                f"[cyan]Tool:[/cyan] {tool}\n"
                f"[cyan]Target:[/cyan] {target}\n"
                f"[cyan]Razón:[/cyan] {reasoning}",
                title="[bold]🔧 Ejecutando[/bold]",
                border_style="blue"
            ))

            if tool == "nmap":
                success, out, err = self.recon.run_nmap(target)
            elif tool == "nikto":
                success, out, err = self.session.run_nikto(target)
            elif tool == "gobuster":
                success, out, err = self.session.run_gobuster(target)
            elif tool == "enum4linux":
                success, out, err = self.session.run_enum4linux(target)
            elif tool == "nuclei":
                success, out, err = self.session.run_nuclei(target)
            else:
                success, out, err = False, "", f"Tool desconocida: {tool}"

            result = out[:3000] if out else err[:1000]  # truncar para el LLM
            self.logger.log_action(tool, target, tool, out, success)

            # Kill switch check
            try:
                self.roe.check_kill_switch(result)
            except RoEViolation as e:
                self.logger.log_roe_violation("KILL_SWITCH", str(e))
                return {**state, "completed": True}

        return {
            **state,
            "current_target": target,
            "messages": state["messages"] + [
                HumanMessage(content=f"Resultado de {tool} en {target}:\n{result}")
            ]
        }

    def _analyze_node(self, state: NemesisState) -> NemesisState:
        """El LLM analiza los resultados y extrae hallazgos."""
        import json, re

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content="Analiza los resultados anteriores. ¿Hay hallazgos de seguridad? Documéntalos o decide el siguiente paso.")
        ] + state["messages"][-15:]

        response = self.llm.invoke(messages)
        content = response.content

        # Extraer hallazgos si los hay
        json_match = re.search(r'\{.*\}', content, re.DOTALL)
        new_findings = list(state["findings"])

        if json_match:
            try:
                data = json.loads(json_match.group())
                if data.get("action") == "finding":
                    finding = {
                        "severity": data.get("severity"),
                        "title": data.get("title"),
                        "target": state.get("current_target"),
                        "description": data.get("description"),
                        "evidence": data.get("evidence", "")
                    }
                    new_findings.append(finding)
                    self.logger.log_finding(
                        finding["severity"],
                        finding["title"],
                        finding["target"],
                        finding["description"],
                        finding["evidence"]
                    )
            except json.JSONDecodeError:
                pass

        return {
            **state,
            "findings": new_findings,
            "messages": state["messages"] + [response]
        }

    def _should_continue(self, state: NemesisState) -> str:
        """Decide si continuar, generar reporte o terminar."""
        if state.get("completed"):
            return "end"

        last_msg = state["messages"][-1]
        content = last_msg.content if hasattr(last_msg, 'content') else ""

        if '"action": "complete"' in content:
            return "report"

        # Límite de iteraciones por seguridad
        if len(state["messages"]) > 40:
            return "report"

        return "continue"

    def _report_node(self, state: NemesisState) -> NemesisState:
        """Genera el reporte final."""
        from src.reporting.report import ReportGenerator

        console.print(Panel(
            f"[green]Engagement completado[/green]\n"
            f"Hallazgos: {len(state['findings'])}",
            title="[bold green]✅ NEMESIS — Reporte Final[/bold green]"
        ))

        reporter = ReportGenerator(self.config)
        reporter.generate(state["findings"], state["targets"])

        return {**state, "completed": True}

    def run(self, targets: List[str]):
        """Punto de entrada principal del agente."""
        self.roe.print_scope()
        console.print(f"\n[bold cyan]🎯 Iniciando engagement contra {len(targets)} target(s)[/bold cyan]\n")

        initial_state: NemesisState = {
            "messages": [],
            "targets": targets,
            "current_target": targets[0] if targets else None,
            "phase": "recon",
            "findings": [],
            "completed": False
        }

        self.graph.invoke(initial_state)
