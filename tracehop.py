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
    [bold bright_green]> SYSTEM COMPROMISED[/]
    [bold green]> INITIATING JS RECON & SECRET SCANNER...[/]
    [dim green]> DEVELOPER - ALINSHAN[/]
    [dim green]> GITHUB - https://github.com/Alinshan/tracehop[/]
    """
    console.print(Panel(banner, border_style="green", expand=False))

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
        SpinnerColumn(style="bold bright_green"),
        TextColumn("[bold bright_green]{task.description}"),
        BarColumn(complete_style="bright_green", finished_style="green"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task(description="> ESTABLISHING CONNECTION...", total=None)
        
        def update_progress(msg):
            progress.update(task, description=f"[bold green]> {msg}[/]")

        if args.pentest:
            results, report_path = await engine.execute_suite(progress_callback=update_progress)
        else:
            results = await engine.run(enumerate_subdomains=enumerate_subdomains, progress_callback=update_progress)

    if args.pentest:
        console.print(f"\n[bold green]>[/] PENTEST SUITE COMPLETE. VULNERABILITIES FOUND: [bold red]{len(results)}[/]")
        for vuln in results:
            color = "red" if vuln['severity'] == "CRITICAL" else "yellow"
            console.print(f"    [dim]-[/] [{color}][{vuln['severity']}][/] {vuln['type']} -> {vuln['host']}")
        
        console.print(f"\n[bold green]>[/] FULL REPORT GENERATED: [underline bright_green]{report_path}[/]")
        return

    if isinstance(results, dict) and "error" in results:
        console.print(f"[bold red]Error:[/] {results['error']}")
        return

    # Print Summary Panel
    summary_text = (
        f"TARGET: [bold bright_green]{engine.domain}[/]\n"
        f"NODES SCANNED: [dim green]{len(engine.targets)}[/]\n"
        f"CRITICAL FINDINGS: [bold bright_green]{len(results)}[/]"
    )
    console.print(Panel(summary_text, title="[blink]>> OPERATION REPORT <<[/]", border_style="green", expand=False))

    # Print Findings Table
    if results:
        table = Table(title="[blink bright_green]** COMPROMISED SECRETS DETECTED **[/]", show_header=True, header_style="bold black on green", border_style="green")
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

    if engine.endpoints:
        console.print(f"\n[bold yellow]>[/] [bold yellow]DISCOVERED {len(engine.endpoints)} API ENDPOINTS/ROUTES:[/]")
        for ep in sorted(list(engine.endpoints))[:15]: # Show max 15 on console
            console.print(f"    [dim]-[/] [bright_yellow]{ep}[/]")
        if len(engine.endpoints) > 15:
            console.print(f"    [dim]... and {len(engine.endpoints) - 15} more (see JSON)[/]")

    # Automatic JSON Output — saved to reports/ folder
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    domain_clean = engine.domain.replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_filename = args.output or f"tracehop_{domain_clean}_{timestamp}.json"
    output_file = reports_dir / output_filename
    
    report_data = {
        "target": engine.domain,
        "timestamp": timestamp,
        "subdomains_found": getattr(engine, 'targets', []),
        "historical_js_found": getattr(engine, 'historical_urls', []),
        "endpoints_count": len(getattr(engine, 'endpoints', [])),
        "endpoints": sorted(list(getattr(engine, 'endpoints', []))),
        "findings_count": len(results),
        "findings": results
    }
    
    with open(output_file, 'w') as f:
        json.dump(report_data, f, indent=4)
    
    console.print(f"\n[bold green]>[/] JSON DATA EXFILTRATED TO: [underline bright_green]{output_file}[/]")

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
