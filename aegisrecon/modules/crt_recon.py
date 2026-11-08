import httpx
from rich.console import Console

console = Console()

def fetch_crt_assets(domain: str) -> tuple[list, list]:
    """Query crt.sh passively to separate subdomains and email addresses."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    emails = set()

    console.print(f"[cyan][*][/cyan] Querying Certificate Transparency logs for [bold]{domain}[/bold]...")

    try:
        with httpx.Client(timeout=30.0, follow_redirects=True) as client:
            response = client.get(url)
            if response.status_code in [404, 502]:
                console.print(f"[yellow][!] Note: crt.sh returned status {response.status_code} (Target may have no public CT logs or service is busy).[/yellow]")
                return [], []
            elif response.status_code != 200:
                console.print(f"[red][!] Error: Received status code {response.status_code} from crt.sh[/red]")
                return [], []

            data = response.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for item in name_value.split("\n"):
                    item = item.strip().lower()
                    if not item or "*" in item:
                        continue
                    
                    if "@" in item and item.endswith(domain):
                        emails.add(item)
                    elif item.endswith(domain):
                        subdomains.add(item)

    except Exception as e:
        console.print(f"[red][!] Connection error while querying crt.sh: {e}[/red]")

    return sorted(subdomains), sorted(emails)
