import typer
import json
import os

from utils.osint.shodan_client import ShodanAdapter
from utils.osint.theharvester_wrapper import TheHarvesterAdapter
from utils.osint.mrholmes_wrapper import MrHolmesAdapter
from utils.osint.cyber_analysis import CyberAnalysisAdapter

app = typer.Typer(help="OSINT CLI Tool and Preset Runner")
osint_app = typer.Typer(help="OSINT Integration Commands")
cyber_app = typer.Typer(help="Authorized cyber analysis commands")
app.add_typer(osint_app, name="osint")
app.add_typer(cyber_app, name="cyber")

# We will attempt to load the Shodan API key from config.json if it exists
def get_shodan_key() -> str:
    key_env = os.getenv("SHODAN_API_KEY", "")
    if key_env:
        return key_env
    
    config_path = "config.json"
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return data.get("shodan_api_key", "")
        except json.JSONDecodeError:
            pass
    return ""

@osint_app.command("shodan")
def shodan_lookup(ip: str = typer.Argument(..., help="IP address to lookup"),
                  search: bool = typer.Option(False, "--search", "-s", help="Treat IP as a search query instead of a direct IP lookup")):
    """
    Run Shodan lookup or search and output unified JSON result.
    """
    api_key = get_shodan_key()
    if not api_key:
        typer.secho("Error: Shodan API key not found in environment (SHODAN_API_KEY) or config.json (shodan_api_key)", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    adapter = ShodanAdapter(api_key=api_key)
    
    if search:
        typer.secho(f"Searching Shodan for '{ip}'...", fg=typer.colors.CYAN)
        result = adapter.search(ip)
    else:
        typer.secho(f"Looking up IP {ip} in Shodan...", fg=typer.colors.CYAN)
        # Wrap the host info into the unified result artificially to just print json
        from utils.osint.model import OSINTUnifiedResult, OSINTMetadata
        import uuid
        
        host_info = adapter.lookup_ip(ip)
        result = OSINTUnifiedResult(
            metadata=OSINTMetadata(run_id=str(uuid.uuid4()), source="shodan_ip", query=ip)
        )
        if host_info:
            result.hosts.append(host_info)

    typer.echo(result.model_dump_json(indent=2))


@osint_app.command("theharvester")
def theharvester_lookup(domain: str, 
                        sources: str = typer.Option("all", help="Data sources (comma separated, or 'all')"),
                        limit: int = typer.Option(500, help="Limit of results")):
    """
    Run theHarvester against a domain and output unified JSON result.
    """
    adapter = TheHarvesterAdapter()
    typer.secho(f"Running theHarvester for {domain} (sources: {sources})...", fg=typer.colors.CYAN)
    
    result = adapter.search_domain(domain=domain, sources=sources, limit=limit)
    typer.echo(result.model_dump_json(indent=2))


@osint_app.command("mrholmes")
def mrholmes_lookup(target: str):
    """
    Run Mr.Holmes wrapper (Mock/Placeholder for now).
    """
    adapter = MrHolmesAdapter(mrholmes_dir="./Mr.Holmes")
    typer.secho(f"Running Mr.Holmes wrapper for {target}...", fg=typer.colors.YELLOW)
    
    result = adapter.run_basic_lookup(target)
    typer.echo(result.model_dump_json(indent=2))


@cyber_app.command("domain")
def cyber_domain(domain: str = typer.Argument(..., help="Domain to analyze")):
    """
    Run passive DNS posture checks for an authorized domain.
    """
    adapter = CyberAnalysisAdapter()
    typer.secho(f"Analyzing domain posture for {domain}...", fg=typer.colors.CYAN)
    result = adapter.analyze_domain(domain)
    typer.echo(result.model_dump_json(indent=2))


@cyber_app.command("url")
def cyber_url(url: str = typer.Argument(..., help="URL to analyze")):
    """
    Inspect HTTP security headers and TLS posture for an authorized URL.
    """
    adapter = CyberAnalysisAdapter()
    typer.secho(f"Analyzing web posture for {url}...", fg=typer.colors.CYAN)
    result = adapter.analyze_url(url)
    typer.echo(result.model_dump_json(indent=2))


@cyber_app.command("host")
def cyber_host(host: str = typer.Argument(..., help="IP address or hostname to analyze")):
    """
    Run reverse DNS and host resolution checks for an authorized host.
    """
    adapter = CyberAnalysisAdapter()
    typer.secho(f"Analyzing host posture for {host}...", fg=typer.colors.CYAN)
    result = adapter.analyze_target(host)
    typer.echo(result.model_dump_json(indent=2))


if __name__ == "__main__":
    app()
