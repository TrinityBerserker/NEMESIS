# ⚔ NEMESIS
### Autonomous Red Team Agent

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![LangGraph](https://img.shields.io/badge/LangGraph-0.2+-1C3A5E?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Kali_Linux-2496ED?style=flat-square&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-v0.1_Alpha-orange?style=flat-square)

> **⚠ FOR AUTHORIZED USE ONLY.**  
> This tool is designed for internal security audits against your own infrastructure or systems you have **explicit written authorization** to test. Unauthorized use against third-party systems is illegal.

---

## What is NEMESIS?

NEMESIS is an **autonomous Red Team agent** that replaces the manual loop of a traditional penetration test with an AI-driven reasoning engine. Instead of an operator manually running `nmap`, reading the output, deciding the next tool, then repeating — NEMESIS does this entire cycle by itself.

A traditional pentest workflow looks like this:

```
Operator → runs nmap → reads output → decides "run nikto on port 80"
       → runs nikto → reads output → decides "try gobuster"
       → runs gobuster → reads output → writes report
```

NEMESIS collapses that loop into an autonomous cycle:

```
NEMESIS → runs nmap → LLM reads output → LLM decides next tool
        → executes tool → LLM analyzes results → extracts findings
        → decides next action → ... → generates report
```

The key insight is that the LLM doesn't just execute commands mechanically — it **reasons** about what the results mean. If nmap finds SMB ports open but no web services, the agent will prioritize `enum4linux` over `nikto`, just as an experienced analyst would. If it finds a service version with known CVEs, it will invoke `nuclei` with the relevant template. The strategy adapts in real time based on what the reconnaissance discovers.

---

## Architecture

NEMESIS is built in three layers that communicate cleanly through well-defined interfaces.

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI (cli.py)                          │
│              Click + Rich — your control surface             │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│              Intelligence Layer (LangGraph)                   │
│                                                               │
│   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌────────┐  │
│   │  plan()  │──▶│execute() │──▶│analyze() │──▶│report()│  │
│   └──────────┘   └──────────┘   └──────────┘   └────────┘  │
│         ▲                                           │        │
│         └───────────── loop until done ────────────┘        │
└────────────────────────┬────────────────────────────────────┘
                         │
          ┌──────────────┼──────────────┐
          │              │              │
┌─────────▼──────┐ ┌────▼──────┐ ┌────▼─────────┐
│ RulesOfEngage- │ │  Audit    │ │  KaliSession  │
│ ment (roe.py)  │ │  Logger   │ │  (session.py) │
│                │ │(logger.py)│ │               │
│ Validates EVERY│ │ Records   │ │ docker exec   │
│ action before  │ │ everything│ │ into Kali     │
│ execution      │ │ to JSONL  │ │ container     │
└────────────────┘ └───────────┘ └──────┬────────┘
                                         │
                               ┌─────────▼──────────┐
                               │   Kali Linux        │
                               │   (Docker)          │
                               │                     │
                               │  nmap  nikto        │
                               │  gobuster  nuclei   │
                               │  enum4linux  ...    │
                               └─────────────────────┘
```

---

## How It Works — Step by Step

Understanding NEMESIS deeply requires understanding each of its components and how they interact.

### 1. Rules of Engagement — the safety layer

Before a single packet leaves your machine, `roe.py` validates the target against your `config.yaml`. It checks three things: whether the IP is inside an authorized network CIDR, whether it's in the explicit exclusion list (your gateway, your management interfaces, your firewall), and whether the current time is within the allowed engagement window if you've enabled time-based restrictions.

This validation happens **twice**: once when you pass the target in the CLI, and again just before each individual tool execution inside the agent loop. This double-check is intentional — the LLM could theoretically hallucinate a target outside scope, and this prevents that from causing real damage.

The `kill_switch_strings` feature adds another safety net. If the output of any tool contains strings like `"domain controller"` or `"PROD-DC"` (configurable), the agent stops all operations immediately. This protects against accidentally stumbling into systems more sensitive than expected.

```yaml
# config.yaml — example RoE configuration
roe:
  authorized_targets:
    - "192.168.10.0/24"
  excluded_targets:
    - "192.168.10.1"      # gateway
    - "192.168.10.254"    # firewall management
  kill_switch_strings:
    - "domain controller"
    - "PROD-DC"
    - "backup server"
```

### 2. The LangGraph State Machine

NEMESIS uses [LangGraph](https://langchain-ai.github.io/langgraph/) to structure the agent as a directed graph of states. Think of it like a flowchart where each box is a function and the arrows are conditional transitions. The graph has four nodes.

**`plan`** receives the full current context — which targets are in scope, the current engagement phase, how many findings have been recorded, and the last 10 messages of conversation history. It responds with a structured JSON object specifying the next action, the target, the tool to use, and its **reasoning**. This reasoning gets logged, so you can audit not just what the agent did but why it decided to do it.

**`execute`** parses the LLM's JSON decision, runs the RoE validation, and sends the command to the Kali container via `docker exec`. The output comes back as raw text and is appended to the graph state. Long outputs are truncated to 3,000 characters before being sent back to the LLM to keep the context window manageable.

**`analyze`** receives the raw tool output and analyzes it for security significance. If it identifies a vulnerability, misconfiguration, or interesting exposure, it responds with a finding JSON containing severity (`CRITICAL/HIGH/MEDIUM/LOW/INFO`), title, description, and evidence. The logger persists this to a JSONL file with a full timestamp.

**`report`** is triggered once the LLM signals completion (or after 40 message iterations as a hard safety limit). The report generator reads all findings from the log, passes them through a Jinja2 HTML template, and writes a dark-themed engagement report to the `reports/` directory.

### 3. Kali Linux as the execution environment

All offensive tooling runs inside a Docker container built on `kalilinux/kali-rolling`. This is a deliberate architectural choice for two reasons: it isolates execution so that if something unexpected happens it stays contained within Docker, and it makes NEMESIS portable so any machine with Docker can run it without managing Kali tool dependencies natively.

The `KaliSession` class abstracts the Docker layer completely. Every command goes through `docker exec nemesis-kali /bin/bash -c "<command>"`, and the result comes back as `(success, stdout, stderr)`. A `local` execution mode is also supported if you're running directly on a Kali host.

### 4. Intelligent reconnaissance parsing

The `ReconAgent` doesn't just hand raw nmap output to the LLM — it also parses it into structured `Host` and `Port` objects. This serves two purposes: it renders a clean table in the terminal in real time, and it enables the `get_interesting_ports()` method to categorize open ports by service type (web, SMB, RDP, VoIP, databases, management interfaces). This categorization gives the orchestrator better signal about what deserves deeper attention.

### 5. Audit logging

Everything gets logged. The `AuditLogger` writes to two files simultaneously: a human-readable `.log` file and a structured `.jsonl` file where each line is a JSON object. Events are typed as `SESSION_START`, `ACTION`, `FINDING`, `ROE_VIOLATION`, or `PHASE`. If the agent ever attempts to go outside scope and gets blocked, that `ROE_VIOLATION` event is also logged — giving you a full audit trail of not just what succeeded, but what was prevented.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/TrinityBerserker/nemesis.git
cd nemesis

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env — add your ANTHROPIC_API_KEY or OPENAI_API_KEY

# Build and start the Kali container
docker-compose -f docker/docker-compose.yml up -d --build

# Verify the environment is ready
python cli.py check
```

---

## Configuration

Before running any scan, edit `config.yaml` to define your engagement scope. The `roe` block is the most critical — nothing runs without passing these checks.

```yaml
engagement:
  name: "Internal Audit Q2-2025"
  operator: "your-name"
  organization: "Your Org"

roe:
  authorized_targets:
    - "192.168.1.0/24"
  excluded_targets:
    - "192.168.1.1"      # always exclude critical infra
  allowed_hours:
    start: "22:00"
    end: "06:00"
    enforce: false        # set true to hard-enforce time window
  kill_switch_strings:
    - "domain controller"
    - "PROD"

modules:
  exploitation:
    enabled: false        # keep false unless you know what you're doing
    require_confirmation: true
```

---

## Usage

```bash
# Check that the Kali environment is reachable
python cli.py check

# Display the currently configured scope
python cli.py scope

# Run a scan against a single host
python cli.py scan --target 192.168.1.10

# Run against multiple specific hosts
python cli.py scan --target 192.168.1.10 --target 192.168.1.20

# Scan a subnet (validate your RoE config first)
python cli.py scan --target 192.168.1.0/24

# Generate an HTML report from the most recent session logs
python cli.py report
```

---

## Active Modules

| Module | Tool | Status | Description |
|--------|------|--------|-------------|
| Recon | `nmap` | ✅ Active | Port scan, service/version detection, OS fingerprinting |
| Web scan | `nikto` | ✅ Active | Web server vulnerability scanning |
| Dir enumeration | `gobuster` | ✅ Active | Web directory and file bruteforcing |
| SMB enumeration | `enum4linux` | ✅ Active | Samba/Windows share and user enumeration |
| Vuln scan | `nuclei` | ✅ Active | Template-based vulnerability detection |
| Exploitation | `metasploit` | ⛔ Disabled | Requires manual activation + explicit RoE |

---

## Output

After each engagement, NEMESIS produces a dark-themed **HTML report** in `reports/` with findings sorted by severity, a **JSONL audit log** in `logs/` with every action and RoE check timestamped to the millisecond, and a **plain text log** for human-readable review.

---

## Roadmap

- [ ] Metasploit integration with confirmation gate
- [ ] AD enumeration module (BloodHound/SharpHound)
- [ ] IDS/EDR evasion validation mode (for testing Darktrace, Sentinel, etc.)
- [ ] Slack/Teams alerting on critical findings
- [ ] PDF report export
- [ ] REST API mode for integration with ticketing systems

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Agent orchestration | [LangGraph](https://langchain-ai.github.io/langgraph/) |
| LLM integration | [LangChain](https://python.langchain.com/) |
| LLM backends | Anthropic Claude, OpenAI GPT-4o |
| Offensive tooling | Kali Linux (Docker) |
| CLI | [Click](https://click.palletsprojects.com/) + [Rich](https://rich.readthedocs.io/) |
| Reporting | [Jinja2](https://jinja.palletsprojects.com/) |

---

## Legal

This software is provided for authorized security testing only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain written authorization before running any security assessment against systems you do not own.

---

*Built by [TrinityBerserker](https://github.com/TrinityBerserker)*
