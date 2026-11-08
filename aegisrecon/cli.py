import argparse
from rich.console import Console
from rich.table import Table
from aegisrecon.modules.crt_recon import fetch_crt_assets
from aegisrecon.modules.dns_audit import audit_dns_records
from aegisrecon.modules.http_probe import probe_subdomains

console = Console()

BANNER = r"""[cyan]
     _               _     ____                      
    / \   ___  __ _ (_)___|  _ \ ___  ___ ___  _ __  
   / _ \ / _ \/ _` || / __| |_) / _ \/ __/ _ \| '_ \ 
  / ___ \  __/ (_| || \__ \  _ <  __/ (_| (_) | | | |
 /_/   \_\___|\__, ||_|___/_| \_\___|\___\___/|_| |_|
              |___/                                  
[/cyan][yellow]Created by Mr. H & Gemini | Kali Linux OSINT Suite[/yellow]"""

def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser(description="AegisRecon - Passive EASM & OSINT Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to scan (e.g., example.com)")
    
    args = parser.parse_args()
    target_domain = args.domain

    console.print(f"\n[bold green][*] Starting reconnaissance on target:[/bold green] {target_domain}\n")

    # 1. Subdomain & Email Enumeration
    subdomains, emails = fetch_crt_assets(target_domain)

    if emails:
        email_table = Table(title=f"Discovered Emails ({len(emails)})", show_lines=True)
        email_table.add_column("No.", style="dim", width=6)
        email_table.add_column("Email Address", style="magenta")

        for idx, email in enumerate(emails, 1):
            email_table.add_row(str(idx), email)

        console.print(email_table)
        console.print("")

    if subdomains:
        table = Table(title=f"Discovered Subdomains ({len(subdomains)})", show_lines=True)
        table.add_column("No.", style="dim", width=6)
        table.add_column("Subdomain", style="cyan")

        for idx, sub in enumerate(subdomains, 1):
            table.add_row(str(idx), sub)

        console.print(table)
        console.print("")

        # 2. HTTP Probing (Only for valid subdomains)
        probe_results = probe_subdomains(subdomains)
        probe_table = Table(title="HTTP/HTTPS Service Probing", show_lines=True)
        probe_table.add_column("Subdomain", style="cyan")
        probe_table.add_column("Status", style="bold green", width=10)
        probe_table.add_column("Server Header", style="yellow")

        for res in probe_results:
            status_style = "green" if res["status"] == "200" else "yellow" if res["status"].isdigit() else "red"
            probe_table.add_row(
                res["subdomain"],
                f"[{status_style}]{res['status']}[/{status_style}]",
                res["server"]
            )
        console.print(probe_table)

    else:
        console.print("[yellow][!] No subdomains found or error occurred during lookup.[/yellow]")

    console.print("")

    # 3. DNS & Email Security Posture Audit
    dns_data = audit_dns_records(target_domain)
    
    dns_table = Table(title="Email Security Posture Audit", show_lines=True)
    dns_table.add_column("Record Type", style="bold magenta", width=15)
    dns_table.add_column("Configuration / Status", style="yellow")

    mx_display = ", ".join(dns_data["mx"]) if dns_data["mx"] else "[red]No MX Records Found[/red]"
    spf_display = dns_data["spf"] if dns_data["spf"] != "Not Found" else "[red]Missing SPF Record (Spoofing Risk)[/red]"
    dmarc_display = dns_data["dmarc"] if dns_data["dmarc"] != "Not Found" else "[red]Missing DMARC Record (Spoofing Risk)[/red]"

    dns_table.add_row("MX Servers", mx_display)
    dns_table.add_row("SPF Policy", spf_display)
    dns_table.add_row("DMARC Policy", dmarc_display)

    console.print(dns_table)

if __name__ == "__main__":
    main()
