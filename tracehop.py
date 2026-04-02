import asyncio
import argparse
import json
import os
import sys
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.live import Live
from scanner.engine import TracehopEngine

console = Console()

def print_banner():
    banner = r"""
  _                       _                 
 | |_ _ __ __ _  ___ ___| |__   ___  _ __  
 | __| '__/ _` |/ __/ _ \ '_ \ / _ \| '_ \ 
 | |_| | | (_| | (__|  __/ | | | (_) | |_) |
  \__|_|  \__,_|\___\___|_| |_|\___/| .__/ 
                                    |_|    
    [bold cyan]Premium JS Recon & Secret Scanner[/]
    [italic dim]Developed By Alinshan - V2.0 (Pro)[/]
    """
    console.print(Panel(banner, border_style="cyan", expand=False))

async def main():
    parser = argparse.ArgumentParser(description="Tracehop - Premium JS Recon & Secret Scanner")
    parser.add_argument("url", help="Target URL to scan (e.g. example.com)")
    parser.add_argument("-s", "--subdomains", action="store_true", help="Enable subdomain enumeration")
    parser.add_argument("-o", "--output", help="Custom output file for JSON report")
    parser.add_argument("--silent", action="store_true", help="Minimal output")
    args = parser.parse_args()

    target_url = args.url
    if not target_url.startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    print_banner()
    
    engine = TracehopEngine(target_url)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task(description="Initializing scan...", total=None)
        
        def update_progress(msg):
            progress.update(task, description=f"[bold cyan]{msg}[/]")

        results = await engine.run(enumerate_subdomains=args.subdomains, progress_callback=update_progress)

    if isinstance(results, dict) and "error" in results:
        console.print(f"[bold red]Error:[/] {results['error']}")
        return

    # Print Summary Panel
    summary_text = (
        f"Target: [bold cyan]{engine.domain}[/]\n"
        f"Subdomains Scanned: [bold white]{len(engine.targets)}[/]\n"
        f"Total Findings: [bold green]{len(results)}[/]"
    )
    console.print(Panel(summary_text, title="Scan Summary", border_style="blue", expand=False))

    # Print Findings Table
    if results:
        table = Table(title="[bold magenta]Secret Findings[/]", show_header=True, header_style="bold cyan", border_style="dim")
        table.add_column("Rule Name", style="bold yellow")
        table.add_column("Secret Snippet", style="green")
        table.add_column("Source Target/File", style="blue")

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
        console.print("\n[bold yellow]![/] No potential secrets discovered.")

    # Automatic JSON Output
    domain_clean = engine.domain.replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = args.output or f"tracehop_{domain_clean}_{timestamp}.json"
    
    report_data = {
        "target": engine.domain,
        "timestamp": timestamp,
        "subdomains_found": engine.targets,
        "findings_count": len(results),
        "findings": results
    }
    
    with open(output_file, 'w') as f:
        json.dump(report_data, f, indent=4)
    
    console.print(f"\n[bold cyan]ℹ[/] JSON report saved to: [underline]{output_file}[/]")

if __name__ == "__main__":
    try:
        # Avoid SSL warnings for large scale scanning
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold red]![/] Scan aborted by user.")
        sys.exit(0)
