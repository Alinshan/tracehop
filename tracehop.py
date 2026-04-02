import asyncio
import argparse
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.live import Live
from rich.prompt import Prompt, Confirm
from scanner.engine import TracehopEngine
from scanner.pentester import PentestEngine

console = Console()

def print_banner():
    banner = r"""
  _                       _                 
 | |_ _ __ __ _  ___ ___| |__   ___  _ __  
 | __| '__/ _` |/ __/ _ \ '_ \ / _ \| '_ \ 
 | |_| | | (_| | (__|  __/ | | | (_) | |_) |
  \__|_|  \__,_|\___\___|_| |_|\___/| .__/ 
                                    |_|    
    [bold blue]> SYSTEM SECURED[/]
    [bold blue]> INITIATING JS RECON & SECRET SCANNER...[/]
    [dim blue]> DEVELOPER - ALINSHAN[/]
    [dim blue]> GITHUB - https://github.com/Alinshan/tracehop[/]
    """
    console.print(Panel(banner, border_style="dodger_blue1", expand=False))

async def main():
    parser = argparse.ArgumentParser(description="Tracehop - Premium JS Recon & Secret Scanner")
    parser.add_argument("url", nargs='?', help="Target URL to scan (e.g. example.com)")
    parser.add_argument("-s", "--subdomains", action="store_true", help="Enable subdomain enumeration")
    parser.add_argument("--pentest", action="store_true", help="Run the full automated Pentest workflow")
    parser.add_argument("--gui", action="store_true", help="Launch the Tracehop Desktop GUI")
    parser.add_argument("--rules", help="Path to a custom YAML rules file")
    parser.add_argument("--user-agents", help="Path to a TXT file with User-Agents (rotated for every request)")
    parser.add_argument("-o", "--output", help="Custom output file for JSON report")
    parser.add_argument("--silent", action="store_true", help="Minimal output")
    args = parser.parse_args()

    if args.gui:
        import gui
        gui.run_gui()
        return

    print_banner()

    target_url = args.url
    enumerate_subdomains = args.subdomains
    
    if not target_url:
        console.print("\n[bold bright_green]>>> INTERACTIVE CONSOLE ENGAGED <<<[/]\n")
        target_url = Prompt.ask("[bold green]>[/] TARGET URL")
        enumerate_subdomains = Confirm.ask("[bold green]>[/] ENABLE SUBDOMAIN ENUMERATION", default=True)
        args_output = Prompt.ask("[bold green]>[/] CUSTOM OUTPUT FILE (Press Enter for auto-generate)", default="")
        args.output = args_output if args_output else None

    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"
    
    # Load User Agents if provided
    user_agents = []
    if args.user_agents and os.path.exists(args.user_agents):
        with open(args.user_agents, 'r') as f:
            user_agents = [line.strip() for line in f if line.strip()]

    if args.pentest:
        engine = PentestEngine(target_url, custom_rules_path=args.rules, user_agents=user_agents)
    else:
        engine = TracehopEngine(target_url, custom_rules_path=args.rules, user_agents=user_agents)
    
    with Progress(
        SpinnerColumn(style="bold dodger_blue1"),
        TextColumn("[bold dodger_blue1]{task.description}"),
        BarColumn(complete_style="dodger_blue1", finished_style="green"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task(description="> ESTABLISHING CONNECTION...", total=None)
        
        def update_progress(msg):
            progress.update(task, description=f"[bold green]> {msg}[/]")

        if args.pentest:
            vulnerabilities, report_path = await engine.execute_suite(progress_callback=update_progress)
            results = engine.main_engine.results # Secrets found during reconnaissance
            recon_data = engine.main_engine.recon_data
        else:
            # Phase 0 for basic scan too
            update_progress("COLLECTING TECHNICAL INTELLIGENCE...")
            await engine.run_reconnaissance()
            results = await engine.run(enumerate_subdomains=enumerate_subdomains, progress_callback=update_progress)
            vulnerabilities = []
            report_path = ""
            recon_data = engine.recon_data

    if isinstance(results, dict) and "error" in results:
        console.print(f"[bold red]Error:[/] {results['error']}")
        return

    # --- CLI Report Section ---
    if args.pentest:
        console.print(f"\n[bold green]>[/] PENTEST SUITE COMPLETE. VULNERABILITIES FOUND: [bold red]{len(vulnerabilities)}[/]")
        for vuln in vulnerabilities:
            color = "red" if vuln['severity'] == "CRITICAL" else "yellow"
            console.print(f"    [dim]-[/] [{color}][{vuln['severity']}][/] {vuln['type']} -> {vuln['host']}")
        
        console.print(f"\n[bold green]>[/] AUDIT REPORT EXPORTED: [underline dodger_blue1]{report_path}[/]")

    # Print Summary Panel (Unified)
    summary_text = (
        f"TARGET: [bold dodger_blue1]{engine.domain if not args.pentest else engine.main_engine.domain}[/]\n"
        f"NODES SCANNED: [dim green]{len(engine.targets if not args.pentest else engine.main_engine.targets)}[/]\n"
        f"CRITICAL FINDINGS: [bold red]{len(results)}[/]"
    )
    console.print(Panel(summary_text, title="> OPERATION REPORT <", border_style="dodger_blue1", expand=False))

    # Print Findings Table (Secrets)
    if results:
        table = Table(title="[bold dodger_blue1]COMPROMISED SECRETS DETECTED[/]", show_header=True, header_style="bold black on dodger_blue1", border_style="dodger_blue1")
        table.add_column("SIGNATURE", style="bold green")
        table.add_column("PAYLOAD SNIPPET", style="bright_green")
        table.add_column("SOURCE NODE", style="dim green")

        for finding in results:
            source_display = finding.get('source', 'unknown')
            if len(source_display) > 50:
                source_display = "..." + source_display[-47:]
            
            # Simple sanitization for display
            secret_display = finding.get('secret', '')
            if len(secret_display) > 40:
                secret_display = secret_display[:37] + "..."
                
            table.add_row(finding.get('rule', 'N/A'), secret_display, source_display)
        
        console.print(table)
    else:
        console.print("\n[dim green]>[/] [bold green]SYSTEM SECURE. NO VULNERABILITIES DETECTED.[/]")

    # --- Phase 0 Summary ---
    if recon_data.get("tech_stack") or recon_data.get("ports"):
        tech_str = ", ".join(recon_data["tech_stack"][:5])
        ports_str = ", ".join(map(str, recon_data["ports"][:10]))
        console.print(f"\n[bold spring_green3]>[/] [bold white]TECH STACK:[/] [dim]{tech_str}[/]")
        console.print(f"[bold spring_green3]>[/] [bold white]OPEN PORTS:[/] [dim]{ports_str}[/]")

    endpoints = getattr(engine, 'endpoints', []) if not args.pentest else engine.main_engine.endpoints
    if endpoints:
        console.print(f"\n[bold yellow]>[/] [bold yellow]DISCOVERED {len(endpoints)} API ENDPOINTS/ROUTES:[/]")
        for ep in sorted(list(endpoints))[:15]: # Show max 15 on console
            console.print(f"    [dim]-[/] [bright_yellow]{ep}[/]")
        if len(endpoints) > 15:
            console.print(f"    [dim]... and {len(endpoints) - 15} more (see JSON)[/]")

    # Automatic JSON Output — saved to reports/ folder
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    domain_clean = (engine.domain if not args.pentest else engine.main_engine.domain).replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = args.output or f"tracehop_{domain_clean}_{timestamp}.json"
    output_file = reports_dir / output_filename
    
    # Extract data correctly from either engine type
    targets = getattr(engine, 'targets', []) if not args.pentest else engine.main_engine.targets
    endpoints = getattr(engine, 'endpoints', []) if not args.pentest else engine.main_engine.endpoints

    report_data = {
        "target": engine.domain if not args.pentest else engine.main_engine.domain,
        "timestamp": timestamp,
        "subdomains_found": targets,
        "historical_js_found": getattr(engine, 'historical_urls', []) if not args.pentest else engine.main_engine.historical_urls,
        "endpoints_count": len(endpoints),
        "endpoints": sorted(list(endpoints)),
        "findings_count": len(results),
        "findings": results,
        "vulnerabilities": vulnerabilities if args.pentest else [],
        "technical_intelligence": recon_data
    }
    
    with open(output_file, 'w') as f:
        json.dump(report_data, f, indent=4)
    
    console.print(f"\n[bold green]>[/] DATA EXFILTRATED TO: [underline spring_green3]{output_file}[/]")

def cli():
    try:
        # Avoid SSL warnings for large scale scanning
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red]![/] Scan aborted by user.")
        sys.exit(0)

if __name__ == "__main__":
    cli()
