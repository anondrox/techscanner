#!/usr/bin/env python3
import argparse
import asyncio
import json
import sys
import os
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.text import Text
from rich.layout import Layout
from rich import box

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.detector import TechDetector

console = Console()


def print_banner():
    banner = """
[bold cyan]
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║                    🔍 T E C H S C A N N E R 🔍 v1.2                       ║
║                                                                            ║
║              Advanced Technology Detection & Analysis Tool                 ║
║                      + CVE Vulnerability Scanning                          ║
║                                                                            ║
║                        [Design by anondrox]                                ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝

    🛡️  Security is not a destination, it's a journey...
    
    🚨 "We've been hacked... again" - CTO, 3:47 AM              
    💻 sudo rm -rf / # Oops... should've used --dry-run
    🔓 "The password is 'Password123!' for maximum security"
    😅 "Nobody's gonna find vulnerabilities in *my* code"
    🎯 "It works on my machine™"
    ⚠️  Me: *commits without running tests* | Prod: *immediately catches fire*
    🐛 "It's not a bug, it's a feature!" - Every developer ever
    📊 "WHAT?! An SQL injection? Impossible!"
    🔐 "Security through obscurity" - Famous last words
    💥 "We'll fix the CVEs in the next sprint... probably"

    Let's scan those technologies and find what's vulnerable! 🎭
[/bold cyan]
    """
    console.print(banner)


def get_confidence_color(confidence: float) -> str:
    if confidence >= 0.9:
        return "green"
    elif confidence >= 0.7:
        return "yellow"
    else:
        return "red"


def get_importance_color(importance: str) -> str:
    if importance == "high":
        return "red"
    elif importance == "medium":
        return "yellow"
    else:
        return "dim"


def get_severity_color(severity: str) -> str:
    severity = severity.upper()
    if severity == "CRITICAL":
        return "bold red"
    elif severity == "HIGH":
        return "red"
    elif severity == "MEDIUM":
        return "yellow"
    elif severity == "LOW":
        return "green"
    else:
        return "dim"


def display_vulnerabilities(vulnerabilities: dict):
    if not vulnerabilities or not vulnerabilities.get('by_technology'):
        return
    
    console.print("\n")
    
    total = vulnerabilities.get('total_cves', 0)
    critical = vulnerabilities.get('critical', 0)
    high = vulnerabilities.get('high', 0)
    medium = vulnerabilities.get('medium', 0)
    low = vulnerabilities.get('low', 0)
    
    summary_parts = []
    if critical > 0:
        summary_parts.append(f"[bold red]{critical} Critical[/bold red]")
    if high > 0:
        summary_parts.append(f"[red]{high} High[/red]")
    if medium > 0:
        summary_parts.append(f"[yellow]{medium} Medium[/yellow]")
    if low > 0:
        summary_parts.append(f"[green]{low} Low[/green]")
    
    summary_text = f"Total CVEs Found: {total}"
    if summary_parts:
        summary_text += " (" + ", ".join(summary_parts) + ")"
    
    console.print(Panel(
        summary_text,
        title="[bold red]Vulnerability Summary[/bold red]",
        box=box.DOUBLE_EDGE,
        style="red" if critical > 0 or high > 0 else "yellow" if medium > 0 else "dim"
    ))
    
    for tech_name, tech_data in vulnerabilities.get('by_technology', {}).items():
        version = tech_data.get('version')
        cves = tech_data.get('cves', [])
        
        if not cves:
            continue
        
        version_str = f" v{version}" if version else ""
        
        cve_table = Table(
            title=f"[bold]{tech_name}{version_str}[/bold] - {len(cves)} CVE(s)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold"
        )
        cve_table.add_column("CVE ID", style="cyan", width=18)
        cve_table.add_column("Severity", justify="center", width=12)
        cve_table.add_column("Score", justify="center", width=8)
        cve_table.add_column("Published", width=12)
        cve_table.add_column("Description", width=50, no_wrap=False)
        
        for cve in cves:
            severity = cve.get('severity', 'UNKNOWN')
            severity_color = get_severity_color(severity)
            score = cve.get('score', 0)
            description = cve.get('description', '') or ''
            
            cve_table.add_row(
                cve.get('id', ''),
                f"[{severity_color}]{severity}[/{severity_color}]",
                f"{score:.1f}" if score else "-",
                cve.get('published', '')[:10],
                description[:100] + "..." if len(description) > 100 else description
            )
        
        console.print(cve_table)
        console.print()


def display_single_result(result: dict, show_details: bool = True, show_cves: bool = False):
    if not result.get('success'):
        console.print(f"\n[red]Error analyzing {result['url']}:[/red] {result.get('error', 'Unknown error')}")
        return
    
    console.print(f"\n[bold cyan]Analysis Results for:[/bold cyan] {result['final_url']}")
    console.print(f"[dim]Analysis completed in {result['analysis_time']}s[/dim]\n")
    
    if result.get('page_info', {}).get('title'):
        console.print(f"[bold]Page Title:[/bold] {result['page_info']['title']}")
    
    technologies = result.get('technologies', [])
    if technologies:
        tech_table = Table(
            title="[bold green]Detected Technologies[/bold green]",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold magenta"
        )
        tech_table.add_column("Technology", style="cyan", width=25)
        tech_table.add_column("Version", style="yellow", width=12)
        tech_table.add_column("Vulnerabilities", style="red", width=35)
        tech_table.add_column("Category", style="white", width=15)
        tech_table.add_column("Confidence", justify="center", width=12)
        
        categories = {}
        for tech in technologies:
            cat = tech['category']
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(tech)
        
        for category, techs in sorted(categories.items()):
            for tech in sorted(techs, key=lambda x: -x['confidence']):
                confidence = tech['confidence']
                color = get_confidence_color(confidence)
                conf_display = f"[{color}]{confidence*100:.0f}%[/{color}]"
                version = tech.get('version') or 'Unknown'
                
                # Display CVE IDs or "No vulnerability detected"
                cves = tech.get('cves', [])
                if cves:
                    cve_display = "[red]" + ", ".join(cves[:2]) + ("[/red]" if len(cves) <= 2 else f" +{len(cves)-2} more[/red]")
                else:
                    cve_display = "[dim]No vulnerability detected[/dim]"
                
                tech_table.add_row(
                    tech['name'],
                    version,
                    cve_display,
                    category,
                    conf_display
                )
        
        console.print(tech_table)
        console.print(f"\n[dim]Total technologies detected: {len(technologies)}[/dim]")
    else:
        console.print("[yellow]No technologies detected[/yellow]")
    
    if show_cves and result.get('vulnerabilities'):
        display_vulnerabilities(result['vulnerabilities'])
    
    if show_details:
        security = result.get('security', {})
        if security:
            console.print("\n")
            
            grade = security.get('grade', 'N/A')
            grade_colors = {
                'A+': 'green', 'A': 'green', 'B': 'yellow',
                'C': 'yellow', 'D': 'red', 'F': 'red'
            }
            grade_color = grade_colors.get(grade, 'white')
            
            console.print(Panel(
                f"[bold {grade_color}]{grade}[/bold {grade_color}]",
                title="[bold]Security Headers Grade[/bold]",
                subtitle=f"Score: {security.get('score', 0)}/{security.get('max_score', 0)}",
                width=30
            ))
            
            if security.get('present'):
                present_table = Table(
                    title="[bold green]Present Security Headers[/bold green]",
                    box=box.SIMPLE,
                    show_header=True
                )
                present_table.add_column("Header", style="green", width=35)
                present_table.add_column("Value", width=50)
                
                for header in security['present']:
                    present_table.add_row(
                        header['header'],
                        header['value']
                    )
                console.print(present_table)
            
            if security.get('missing'):
                missing_table = Table(
                    title="[bold red]Missing Security Headers[/bold red]",
                    box=box.SIMPLE,
                    show_header=True
                )
                missing_table.add_column("Header", style="red", width=35)
                missing_table.add_column("Importance", width=12)
                missing_table.add_column("Description", width=40)
                
                for header in sorted(security['missing'], key=lambda x: {'high': 0, 'medium': 1, 'low': 2}.get(x['importance'], 3)):
                    imp_color = get_importance_color(header['importance'])
                    missing_table.add_row(
                        header['header'],
                        f"[{imp_color}]{header['importance']}[/{imp_color}]",
                        header['description']
                    )
                console.print(missing_table)
        
        performance = result.get('performance', {})
        if performance:
            console.print("\n")
            perf_items = []
            
            if performance.get('compression'):
                perf_items.append(f"[green]Compression:[/green] {performance['compression']}")
            else:
                perf_items.append("[red]Compression:[/red] Not enabled")
            
            caching = performance.get('caching') or {}
            if caching:
                cache_info = ", ".join([f"{k}: {v}" for k, v in caching.items() if v])
                cache_display = (cache_info[:60] + "...") if cache_info else "No cache headers"
                perf_items.append(f"[green]Caching:[/green] {cache_display}")
            else:
                perf_items.append("[yellow]Caching:[/yellow] No cache headers found")
            
            if performance.get('lazy_loading'):
                perf_items.append("[green]Lazy Loading:[/green] Enabled")
            
            preload = performance.get('preload') or []
            if preload:
                perf_items.append(f"[green]Preloaded Resources:[/green] {len(preload)} items")
            
            console.print(Panel(
                "\n".join(perf_items),
                title="[bold]Performance Indicators[/bold]",
                box=box.ROUNDED
            ))


def display_batch_summary(results: List[dict], show_cves: bool = False):
    console.print("\n")
    
    summary_table = Table(
        title="[bold cyan]Batch Analysis Summary[/bold cyan]",
        box=box.DOUBLE_EDGE,
        show_header=True,
        header_style="bold"
    )
    summary_table.add_column("URL", style="cyan", width=35, no_wrap=True)
    summary_table.add_column("Status", justify="center", width=8)
    summary_table.add_column("Techs", justify="center", width=8)
    summary_table.add_column("Grade", justify="center", width=8)
    if show_cves:
        summary_table.add_column("CVEs", justify="center", width=8)
    summary_table.add_column("Time", justify="right", width=6)
    
    for result in results:
        url = result.get('final_url', result.get('url', 'Unknown')) or 'Unknown'
        if url and len(url) > 33:
            url = url[:30] + "..."
        
        if result.get('success'):
            status = "[green]OK[/green]"
            tech_count = len(result.get('technologies', []))
            grade = result.get('security', {}).get('grade', 'N/A')
            grade_colors = {'A+': 'green', 'A': 'green', 'B': 'yellow', 'C': 'yellow', 'D': 'red', 'F': 'red'}
            grade_display = f"[{grade_colors.get(grade, 'white')}]{grade}[/{grade_colors.get(grade, 'white')}]"
            time_str = f"{result.get('analysis_time', 0)}s"
            
            if show_cves:
                cve_count = result.get('vulnerabilities', {}).get('total_cves', 0)
                cve_display = f"[red]{cve_count}[/red]" if cve_count > 0 else "0"
                summary_table.add_row(url, status, str(tech_count), grade_display, cve_display, time_str)
            else:
                summary_table.add_row(url, status, str(tech_count), grade_display, time_str)
        else:
            status = "[red]FAIL[/red]"
            if show_cves:
                summary_table.add_row(url, status, "-", "-", "-", "-")
            else:
                summary_table.add_row(url, status, "-", "-", "-")
    
    console.print(summary_table)
    
    successful = sum(1 for r in results if r.get('success'))
    failed = len(results) - successful
    total_time = sum(r.get('analysis_time', 0) for r in results if r.get('success'))
    
    console.print(f"\n[bold]Summary:[/bold] {successful} successful, {failed} failed, Total time: {total_time:.1f}s")


def save_results(results: List[dict], output_path: str, format_type: str = 'json'):
    if format_type == 'json':
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
    elif format_type == 'csv':
        import csv
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Status', 'Technologies', 'Security Grade', 'CVE Count', 'Analysis Time'])
            for result in results:
                url = result.get('final_url', result.get('url', ''))
                status = 'Success' if result.get('success') else 'Failed'
                techs = '; '.join([t['name'] for t in result.get('technologies', [])])
                grade = result.get('security', {}).get('grade', 'N/A')
                cve_count = result.get('vulnerabilities', {}).get('total_cves', 0)
                time_val = result.get('analysis_time', 0)
                writer.writerow([url, status, techs, grade, cve_count, time_val])
    
    console.print(f"\n[green]Results saved to:[/green] {output_path}")


async def run_analysis(urls: List[str], concurrency: int, show_details: bool, 
                       enable_cve: bool = False, nvd_api_key: Optional[str] = None):
    detector = TechDetector(timeout=20, enable_cve=enable_cve, nvd_api_key=nvd_api_key)
    
    urls = urls or []
    if len(urls) == 1:
        status_msg = "[bold green]Analyzing"
        if enable_cve:
            status_msg += " (with CVE lookup - this may take longer)"
        status_msg += "...[/bold green]"
        
        with console.status(status_msg):
            result = await detector.analyze_url(urls[0])
        display_single_result(result, show_details, show_cves=enable_cve)
        return [result]
    else:
        results = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            desc = f"[cyan]Analyzing {len(urls)} URLs"
            if enable_cve:
                desc += " (with CVE lookup)"
            desc += "..."
            task = progress.add_task(desc, total=len(urls))
            
            results = await detector.analyze_urls(urls, concurrency)
            progress.update(task, completed=len(urls))
        
        display_batch_summary(results, show_cves=enable_cve)
        
        if show_details:
            for result in results:
                if result.get('success'):
                    console.print("\n" + "="*70)
                    display_single_result(result, show_details=True, show_cves=enable_cve)
        
        return results


def main():
    parser = argparse.ArgumentParser(
        description="TechScanner - Advanced Technology Detection Tool with CVE Scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s https://example.com                   # Analyze a single URL
  %(prog)s https://example.com --cve             # Analyze with CVE vulnerability scan
  %(prog)s https://example.com -o results.json   # Save results to JSON
  %(prog)s -f urls.txt                           # Batch analyze from file
  %(prog)s -f urls.txt -c 10 --cve               # Batch with CVE scanning
  %(prog)s https://example.com --brief           # Show only technologies

CVE Scanning:
  Use --cve to enable vulnerability scanning via the NIST NVD database.
  Set NVD_API_KEY environment variable for faster API access (10x rate limit).
  Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key
        """
    )
    
    parser.add_argument('url', nargs='?', help='URL to analyze')
    parser.add_argument('-f', '--file', help='File containing URLs (one per line)')
    parser.add_argument('-o', '--output', help='Output file path (supports .json and .csv)')
    parser.add_argument('-c', '--concurrency', type=int, default=5, help='Number of concurrent requests (default: 5)')
    parser.add_argument('--cve', action='store_true', help='Enable CVE vulnerability scanning (uses NIST NVD API)')
    parser.add_argument('--brief', action='store_true', help='Show only technologies without security/performance details')
    parser.add_argument('--json', action='store_true', help='Output raw JSON to stdout')
    parser.add_argument('--no-banner', action='store_true', help='Hide the banner')
    parser.add_argument('-v', '--version', action='version', version='TechScanner 1.2.0')
    
    args = parser.parse_args()
    
    urls = []
    
    if args.url:
        urls.append(args.url)
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                file_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                urls.extend(file_urls)
        except FileNotFoundError:
            console.print(f"[red]Error:[/red] File not found: {args.file}")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Error reading file:[/red] {e}")
            sys.exit(1)
    
    if not urls:
        parser.print_help()
        console.print("\n[yellow]Error:[/yellow] Please provide a URL or a file with URLs")
        sys.exit(1)
    
    if not args.no_banner and not args.json:
        print_banner()
    
    nvd_api_key = os.environ.get('NVD_API_KEY')
    
    if args.cve and not nvd_api_key:
        console.print("\n[bold cyan]CVE Vulnerability Scanning[/bold cyan]")
        if sys.stdin.isatty():
            user_input = console.input("[cyan]Enter your NVD API key (or press Enter to continue with public API): [/cyan]").strip()
            if user_input:
                nvd_api_key = user_input
                console.print("[green]✓ API key provided[/green]")
            else:
                console.print("[yellow]Note:[/yellow] Using public API with rate limits (50 requests per 30 seconds).")
        else:
            console.print("[yellow]Note:[/yellow] Using public API with rate limits (50 requests per 30 seconds).")
        console.print("[dim]Get a free API key at: https://nvd.nist.gov/developers/request-an-api-key[/dim]\n")
    
    try:
        results = asyncio.run(run_analysis(
            urls, 
            args.concurrency, 
            not args.brief,
            enable_cve=args.cve,
            nvd_api_key=nvd_api_key
        ))
        
        if args.json:
            print(json.dumps(results, indent=2))
        elif args.output:
            if args.output.endswith('.csv'):
                save_results(results, args.output, 'csv')
            else:
                save_results(results, args.output, 'json')
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]Error:[/red] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
