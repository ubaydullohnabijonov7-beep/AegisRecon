import httpx
from rich.console import Console

console = Console()

def probe_subdomains(subdomains: list) -> list:
    """Probes discovered subdomains for active HTTP/HTTPS services and status codes."""
    results = []
    console.print(f"[cyan][*][/cyan] Probing subdomains for HTTP/HTTPS live status...")

    with httpx.Client(timeout=5.0, follow_redirects=True) as client:
        for sub in subdomains:
            active_url = None
            status_code = "Offline"
            server_header = "N/A"

            for proto in ["https", "http"]:
                target_url = f"{proto}://{sub}"
                try:
                    response = client.get(target_url)
                    active_url = target_url
                    status_code = str(response.status_code)
                    server_header = response.headers.get("Server", "Unknown")
                    break
                except Exception:
                    continue

            results.append({
                "subdomain": sub,
                "url": active_url if active_url else f"http://{sub}",
                "status": status_code,
                "server": server_header
            })

    return results
