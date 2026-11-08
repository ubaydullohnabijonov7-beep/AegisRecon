import dns.resolver
from rich.console import Console

console = Console()

def audit_dns_records(domain: str) -> dict:
    """Audits DNS records for mail servers (MX), SPF (TXT), and DMARC posture."""
    results = {
        "mx": [],
        "spf": "Not Found",
        "dmarc": "Not Found"
    }

    console.print(f"[cyan][*][/cyan] Auditing DNS & Email Security posture for [bold]{domain}[/bold]...")

    try:
        mx_answers = dns.resolver.resolve(domain, 'MX')
        for rdata in mx_answers:
            results["mx"].append(str(rdata.exchange).rstrip('.'))
    except Exception:
        pass

    try:
        txt_answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in txt_answers:
            txt_str = rdata.to_text().strip('"')
            if "v=spf1" in txt_str:
                results["spf"] = txt_str
                break
    except Exception:
        pass

    try:
        dmarc_domain = f"_dmarc.{domain}"
        dmarc_answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in dmarc_answers:
            dmarc_str = rdata.to_text().strip('"')
            if "v=DMARC1" in dmarc_str:
                results["dmarc"] = dmarc_str
                break
    except Exception:
        pass

    return results
