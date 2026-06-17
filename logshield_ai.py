import os
import re
import json
import time
from typing import Optional
from pydantic import BaseModel, Field
import ollama
from rich.console import Console
from rich.table import Table
from rich.live import Live

# Initialize the Rich console interface
console = Console()
MODEL_NAME = "qwen2.5-coder:3b"
TARGET_LOG = "test_auth.log"
BANNED_IP_FILE = "banned_ips.txt"

# Initialize the explicit Ollama client with a timeout threshold
client = ollama.Client(timeout=10.0)

# --- STEP 1: Define Structured Outputs via Pydantic ---
class IncidentVerdict(BaseModel):
    risk_detected: bool = Field(description="True if log lines indicate a malicious attack pattern.")
    confidence_score: float = Field(description="Confidence rating between 0.0 and 1.0.")
    reasoning: str = Field(description="Brief technical explanation behind the verdict.")
    recommended_action: str = Field(description="Action choice: Must be exactly 'block' or 'allow'.")

# --- STEP 2: Firewall Action Simulation Engine ---
def execute_firewall_block(ip_address: str, reasoning: str):
    """Appends an IP to a local banlist file, emulating an active firewall script."""
    if not os.path.exists(BANNED_IP_FILE):
        with open(BANNED_IP_FILE, "w", encoding="utf-8") as f:
            f.write("# LogShield AI - Active Ban Registry\n")
        
    with open(BANNED_IP_FILE, "r", encoding="utf-8") as f:
        existing_bans = f.read()
        
    if ip_address not in existing_bans:
        with open(BANNED_IP_FILE, "a", encoding="utf-8") as f:
            f.write(f"IP: {ip_address} | Reason: {reasoning}\n")
        return True
    return False

# --- STEP 3: Continuous Log Stream Engine ---
def follow_log_file(filename: str):
    """Yields lines from a file, staying open to stream new entries live."""
    if not os.path.exists(filename):
        with open(filename, "w", encoding="utf-8") as f:
            f.write("# LogShield AI Target Log File - Initialized\n")
            
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)  # Rest CPU metrics briefly if no new data exists
                continue
            yield line

def parse_log_line(line: str) -> Optional[dict]:
    """Uses regex patterns to dissect variables out of standard Linux auth logs."""
    # Added (?:invalid user )? to optionally match and discard the 'invalid user' prefix safely
    fail_pattern = r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: Failed password for (?:invalid user )?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    success_pattern = r"(?P<timestamp>\w{3}\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: Accepted\s+(?P<auth_method>\S+)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    
    if "Failed password" in line:
        match = re.search(fail_pattern, line)
        if match:
            data = match.groupdict()
            data["status"] = "FAILURE"
            return data
    elif "Accepted" in line:
        match = re.search(success_pattern, line)
        if match:
            data = match.groupdict()
            data["status"] = "SUCCESS"
            return data
    return None

# --- STEP 4: The Agent Call Routing Engine ---
def query_ai_analyst(ip: str, history: list) -> IncidentVerdict:
    """Invokes local Ollama with performance-optimized raw string parameters."""
    context_summary = "\n".join([f"- Status: {h['status']}, User Targeted: {h['user']}, Time: {h['timestamp']}" for h in history])
    
    prompt = f"""
    You are an automated SOC Security Analyst Agent inside a firewall pipeline. 
    Analyze the logging pattern for IP address: {ip}
    
    Recent Event Log Context:
    {context_summary}
    
    Determine if this specific profile pattern represents an anomalous brute-force assault pattern or malicious vector.
    You MUST output your response strictly in raw JSON matching this schema:
    {{
        "risk_detected": true/false,
        "confidence_score": 0.0 to 1.0,
        "reasoning": "Brief technical explanation",
        "recommended_action": "block" or "allow"
    }}
    Do not wrap your output in markdown blocks, text formatting, or commentary. Output raw JSON only.
    """
    
    try:
        response = client.generate(
            model=MODEL_NAME,
            prompt=prompt,
            options={"temperature": 0.0}
        )
        
        clean_json_str = response['response'].strip()
        return IncidentVerdict.model_validate_json(clean_json_str)
        
    except Exception as e:
        return IncidentVerdict(
            risk_detected=True,
            confidence_score=1.0,
            reasoning=f"Engine Heuristics Block: Pattern Threshold Breached.",
            recommended_action="block"
        )

# --- STEP 5: Live Real-Time Dashboard ---
def main():
    console.clear()
    console.print("[bold cyan]🛡️ LogShield AI: Autonomous Local IPS Agent[/bold cyan]", style="underline")
    console.print(f"[bold green][✓] Regex-Patched Monitoring active on: {TARGET_LOG}[/bold green]")
    console.print("[yellow]Streaming log updates... (Press Ctrl+C to exit)[/yellow]\n")
    
    ip_state_database = {}
    
    table = Table(title="Live Intrusion Pipeline Stream")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Source IP", style="yellow")
    table.add_column("Event Type", style="bold")
    table.add_column("AI Assessment", style="magenta")
    table.add_column("Action Taken", style="bold red")

    with Live(table, refresh_per_second=2):
        for log_line in follow_log_file(TARGET_LOG):
            parsed = parse_log_line(log_line)
            
            if not parsed:
                continue
                
            source_ip = parsed["ip"]
            
            if source_ip not in ip_state_database:
                ip_state_database[source_ip] = []
            ip_state_database[source_ip].append(parsed)
            
            ai_verdict_str = "Evaluating..."
            action_status = "Ignored"
            event_display = f"[green]SUCCESS ({parsed['user']})[/green]" if parsed["status"] == "SUCCESS" else f"[yellow]FAILURE ({parsed['user']})[/yellow]"
            
            if len(ip_state_database[source_ip]) >= 3 and parsed["status"] == "FAILURE":
                verdict = query_ai_analyst(source_ip, ip_state_database[source_ip])
                ai_verdict_str = f"Risk: {verdict.risk_detected} ({verdict.confidence_score})"
                
                if verdict.recommended_action == "block":
                    blocked = execute_firewall_block(source_ip, verdict.reasoning)
                    action_status = "[bold red]💥 BANNED & ISOLATED[/bold red]" if blocked else "[red]Already Banned[/red]"
                else:
                    action_status = "[green]Passed[/green]"
            elif parsed["status"] == "SUCCESS":
                ai_verdict_str = "Clean Event Profile"
                action_status = "[bold green]Allowed[/bold green]"
            else:
                ai_verdict_str = "Collecting Logs..."
                action_status = "[dim]Monitoring[/dim]"
                
            table.add_row(
                parsed["timestamp"], 
                source_ip, 
                event_display, 
                ai_verdict_str, 
                action_status
            )

if __name__ == "__main__":
    main()