import json
import os

import typer

from audit_platform import auth, inventory, scheduler, storage
from audit_platform.osint.cyber_analysis import CyberAnalysisAdapter
from audit_platform.osint.shodan_client import ShodanAdapter
from audit_platform.osint.theharvester_wrapper import TheHarvesterAdapter
from audit_platform.scoring import score_findings

app = typer.Typer(help="OSINT CLI Tool and Preset Runner")
osint_app = typer.Typer(help="OSINT Integration Commands")
cyber_app = typer.Typer(help="Authorized cyber analysis commands")
asset_app = typer.Typer(help="Asset inventory management")
fleet_app = typer.Typer(help="Fleet-wide audit operations")
user_app = typer.Typer(help="User and access management")
app.add_typer(osint_app, name="osint")
app.add_typer(cyber_app, name="cyber")
app.add_typer(asset_app, name="asset")
app.add_typer(fleet_app, name="fleet")
app.add_typer(user_app, name="user")

# Resolve the Shodan API key. Environment variables are the supported source;
# reading it from config.json is kept only as a deprecated fallback so that a
# committed config.json never becomes the canonical place to store secrets.
def get_shodan_key() -> str:
    key_env = os.getenv("SHODAN_API_KEY", "")
    if key_env:
        return key_env

    config_path = "config.json"
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
            key_cfg = data.get("shodan_api_key", "")
            if key_cfg:
                typer.secho(
                    "Warning: reading Shodan API key from config.json is deprecated. "
                    "Set the SHODAN_API_KEY environment variable instead and keep secrets out of config.json.",
                    fg=typer.colors.YELLOW,
                )
            return key_cfg
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
        import uuid

        from audit_platform.osint.model import OSINTMetadata, OSINTUnifiedResult

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


@osint_app.command("nmap")
def nmap_scan(
    target: str = typer.Argument(..., help="Host or network to scan"),
    enrich: bool = typer.Option(False, "--enrich", help="Enrich detected CVEs with CVSS from NVD/OSV"),
):
    """
    Run an Nmap vulnerability scan and optionally enrich CVEs with CVSS intelligence.
    """
    from audit_platform.osint import vuln_intel
    from audit_platform.osint.nmap_wrapper import NmapAdapter

    adapter = NmapAdapter()
    typer.secho(f"Scanning {target} with Nmap (vulners)...", fg=typer.colors.CYAN)
    result = adapter.vuln_scan(target)

    if enrich:
        typer.secho("Enriching CVEs with CVSS scores...", fg=typer.colors.CYAN)
        vulns = vuln_intel.enrich_osint_result(result)
        if vulns:
            findings = vuln_intel.vulnerabilities_to_findings(vulns)
            posture = score_findings(findings)
            typer.secho(f"\nVulnerability posture: {posture.score}/100 ({posture.grade})", fg=_grade_color(posture.grade), bold=True)
            for v in sorted(vulns, key=lambda x: x.cvss_score or 0, reverse=True):
                typer.echo(f"  [{v.severity.upper()}] {v.cve_id} CVSS={v.cvss_score} ({v.source})")
        else:
            typer.secho("No CVEs detected in scan output.", fg=typer.colors.GREEN)
    else:
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


def _grade_color(grade: str):
    return {
        "A": typer.colors.GREEN,
        "B": typer.colors.GREEN,
        "C": typer.colors.YELLOW,
        "D": typer.colors.YELLOW,
        "F": typer.colors.RED,
    }.get(grade, typer.colors.WHITE)


@cyber_app.command("audit")
def cyber_audit(
    target: str = typer.Argument(..., help="Domain, URL or host to audit"),
    save: bool = typer.Option(True, "--save/--no-save", help="Persist this audit to the history database"),
    json_output: bool = typer.Option(False, "--json", help="Print the full report as JSON instead of a summary"),
):
    """
    Run a full posture audit: analyze the target, score it, and persist the result for drift tracking.
    """
    adapter = CyberAnalysisAdapter()
    typer.secho(f"Auditing {target}...", fg=typer.colors.CYAN)
    report = adapter.analyze_target(target)

    findings = [f.model_dump() for f in report.findings]
    posture = score_findings(report.findings)

    if save:
        storage.save_scan(
            target=report.target,
            source=report.metadata.source,
            score=posture.score,
            grade=posture.grade,
            findings=findings,
            report=report.model_dump(mode="json"),
            run_id=report.metadata.run_id,
        )

    if json_output:
        payload = report.model_dump(mode="json")
        payload["posture"] = posture.model_dump()
        typer.echo(json.dumps(payload, indent=2, default=str))
        return

    typer.secho(
        f"\nPosture score: {posture.score}/100  Grade: {posture.grade}",
        fg=_grade_color(posture.grade),
        bold=True,
    )
    typer.echo(f"Findings: {posture.findings_total}  ({dict(posture.severity_counts)})")
    for finding in report.findings:
        color = typer.colors.RED if finding.severity in ("critical", "high") else typer.colors.YELLOW
        typer.secho(f"  [{finding.severity.upper()}] {finding.category}: {finding.detail}", fg=color)
    if save:
        typer.secho("\nSaved to audit history. Run 'cyber diff' to compare against the next audit.", fg=typer.colors.CYAN)


@cyber_app.command("diff")
def cyber_diff(target: str = typer.Argument(..., help="Target whose last two audits to compare")):
    """
    Show what changed between the two most recent audits of a target (drift detection).
    """
    result = storage.diff_scans(target)
    if result is None:
        typer.secho(f"Not enough history for '{target}'. Run 'cyber audit {target}' at least twice.", fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)

    delta = result["score_delta"]
    delta_color = typer.colors.GREEN if delta > 0 else typer.colors.RED if delta < 0 else typer.colors.WHITE
    typer.secho(f"Drift report for {target}", bold=True)
    typer.echo(f"  Previous: {result['previous']['score']}/100 ({result['previous']['grade']}) at {result['previous']['timestamp']}")
    typer.echo(f"  Current:  {result['current']['score']}/100 ({result['current']['grade']}) at {result['current']['timestamp']}")
    typer.secho(f"  Score change: {delta:+d}", fg=delta_color, bold=True)

    if result["new_findings"]:
        typer.secho("\n  New issues:", fg=typer.colors.RED)
        for f in result["new_findings"]:
            typer.echo(f"    + [{f.get('severity', '').upper()}] {f.get('category')}: {f.get('detail')}")
    if result["resolved_findings"]:
        typer.secho("\n  Resolved issues:", fg=typer.colors.GREEN)
        for f in result["resolved_findings"]:
            typer.echo(f"    - [{f.get('severity', '').upper()}] {f.get('category')}: {f.get('detail')}")
    if not result["new_findings"] and not result["resolved_findings"]:
        typer.secho("\n  No change in findings.", fg=typer.colors.CYAN)


@cyber_app.command("report")
def cyber_report(
    target: str = typer.Argument(..., help="Target to audit and report on"),
    output: str = typer.Option("", "--output", "-o", help="Output file path (HTML or PDF based on extension, defaults to audit_report.html)"),
    pdf: bool = typer.Option(False, "--pdf", help="Export to native PDF instead of HTML"),
):
    """
    Audit a target and write a branded HTML or native PDF audit report.
    """
    from audit_platform import reporting

    adapter = CyberAnalysisAdapter()
    typer.secho(f"Auditing {target} and building report...", fg=typer.colors.CYAN)
    report = adapter.analyze_target(target)
    posture = score_findings(report.findings)

    history = [s["score"] for s in reversed(storage.get_recent_scans(report.target, limit=10))]
    history.append(posture.score)

    is_pdf = pdf or (output and output.lower().endswith(".pdf"))
    if not output:
        output = "audit_report.pdf" if is_pdf else "audit_report.html"

    if is_pdf:
        path = reporting.generate_pdf_report(report.model_dump(mode="json"), posture, output, history_scores=history)
    else:
        path = reporting.save_html_report(report.model_dump(mode="json"), posture, output, history_scores=history)

    typer.secho(f"Report written to {path} ({posture.score}/100 {posture.grade}).", fg=_grade_color(posture.grade))


@cyber_app.command("compliance")
def cyber_compliance(
    target: str = typer.Argument(..., help="Target to evaluate"),
    framework: str = typer.Option("OWASP-ASVS", help="Framework: OWASP-ASVS, CIS, PCI-DSS, NIST-CSF"),
):
    """
    Audit a target and show its compliance scorecard for a framework.
    """
    from audit_platform import compliance

    adapter = CyberAnalysisAdapter()
    report = adapter.analyze_target(target)
    findings = [f.model_dump() for f in report.findings]
    try:
        scorecard = compliance.evaluate_compliance(findings, framework)
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=2) from exc

    color = typer.colors.GREEN if scorecard.compliance_percent >= 80 else typer.colors.YELLOW if scorecard.compliance_percent >= 50 else typer.colors.RED
    typer.secho(f"\n{framework}: {scorecard.compliance_percent}% compliant ({scorecard.controls_compliant}/{scorecard.controls_total})", fg=color, bold=True)
    for c in scorecard.controls:
        mark = "✓" if c.compliant else "✗"
        c_color = typer.colors.GREEN if c.compliant else typer.colors.RED
        typer.secho(f"  {mark} {c.control_id}: {c.title}", fg=c_color)


@cyber_app.command("remediate")
def cyber_remediate(target: str = typer.Argument(..., help="Target to audit and produce a remediation plan for")):
    """
    Audit a target and produce a prioritized remediation plan (AI-assisted when ANTHROPIC_API_KEY is set).
    """
    from audit_platform import ai_remediation

    adapter = CyberAnalysisAdapter()
    typer.secho(f"Auditing {target} and building remediation plan...", fg=typer.colors.CYAN)
    report = adapter.analyze_target(target)
    findings = [f.model_dump() for f in report.findings]

    mode = "AI-assisted (Claude)" if ai_remediation.is_available() else "heuristic (set ANTHROPIC_API_KEY for AI)"
    typer.secho(f"Remediation mode: {mode}", fg=typer.colors.CYAN)
    plan = ai_remediation.generate_remediation(findings)

    if not plan:
        typer.secho("No findings to remediate. ✅", fg=typer.colors.GREEN)
        return
    for item in plan:
        color = typer.colors.RED if item.exploitability == "high" else typer.colors.YELLOW
        typer.secho(f"  #{item.priority} [{item.severity.upper()}/exploit:{item.exploitability}] {item.category}", fg=color, bold=True)
        typer.echo(f"      → {item.remediation}")


@cyber_app.command("history")
def cyber_history():
    """
    List all audited targets with their latest posture score, worst first.
    """
    targets = storage.list_targets()
    if not targets:
        typer.secho("No audit history yet. Run 'cyber audit <target>' to start tracking.", fg=typer.colors.YELLOW)
        return
    typer.secho("Audited targets (worst posture first):", bold=True)
    for entry in targets:
        typer.secho(
            f"  {entry['grade']}  {entry['score']:>3}/100  {entry['target']}  (last: {entry['timestamp']})",
            fg=_grade_color(entry["grade"]),
        )


@asset_app.command("add")
def asset_add(
    name: str = typer.Argument(..., help="Friendly name for the asset"),
    target: str = typer.Argument(..., help="Domain, URL or host"),
    asset_type: str = typer.Option("domain", "--type", help="domain | url | host"),
    group: str = typer.Option("default", help="Logical group"),
    environment: str = typer.Option("production", help="Environment (production/staging/...)"),
    owner: str = typer.Option("", help="Responsible owner"),
    tags: str = typer.Option("", help="Comma-separated tags"),
    tenant: str = typer.Option("default", help="Tenant the asset belongs to"),
):
    """Register (or update) an asset in the inventory."""
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    asset_id = inventory.add_asset(
        name=name, target=target, asset_type=asset_type, group=group,
        tags=tag_list, environment=environment, owner=owner, tenant=tenant,
    )
    typer.secho(f"Asset '{name}' saved (id={asset_id}).", fg=typer.colors.GREEN)


@asset_app.command("list")
def asset_list(tenant: str = typer.Option(None, help="Filter by tenant")):
    """List inventory assets."""
    assets = inventory.list_assets(tenant=tenant)
    if not assets:
        typer.secho("No assets registered. Use 'asset add'.", fg=typer.colors.YELLOW)
        return
    for a in assets:
        typer.echo(f"  [{a['id']}] {a['name']} -> {a['target']} ({a['asset_type']}, {a['asset_group']}/{a['environment']}, tenant={a['tenant']})")


@asset_app.command("remove")
def asset_remove(asset_id: int = typer.Argument(..., help="Asset id to remove")):
    """Remove an asset from the inventory."""
    if inventory.delete_asset(asset_id):
        typer.secho(f"Asset {asset_id} removed.", fg=typer.colors.GREEN)
    else:
        typer.secho(f"Asset {asset_id} not found.", fg=typer.colors.RED)
        raise typer.Exit(code=1)


@fleet_app.command("audit")
def fleet_audit(tenant: str = typer.Option(None, help="Audit only this tenant's assets")):
    """Audit every asset in the inventory, persist results and fire alerts on drift."""
    typer.secho("Running fleet audit...", fg=typer.colors.CYAN)
    results = scheduler.run_fleet_audit(tenant=tenant)
    if not results:
        typer.secho("No assets to audit. Register some with 'asset add'.", fg=typer.colors.YELLOW)
        return
    for r in results:
        if "error" in r:
            typer.secho(f"  ✗ {r['asset']} ({r['target']}): {r['error']}", fg=typer.colors.RED)
        else:
            alert_note = f" ⚠ {len(r['alerts'])} alert(s)" if r["alerts"] else ""
            typer.secho(f"  ✓ {r['asset']} ({r['target']}): {r['score']}/100 {r['grade']}{alert_note}", fg=_grade_color(r["grade"]))


@fleet_app.command("scheduler")
def fleet_scheduler(
    interval: int = typer.Option(3600, "--interval", "-i", help="Interval between runs in seconds"),
    tenant: str = typer.Option(None, help="Audit only this tenant's assets"),
):
    """Run the fleet scheduler daemon to continuously audit assets at configured intervals."""
    import signal
    import threading
    import time

    typer.secho(f"Starting Fleet Scheduler daemon (interval={interval}s, tenant={tenant or 'all'})...", fg=typer.colors.CYAN)

    sched = scheduler.FleetScheduler(interval_seconds=interval, tenant=tenant)

    stop_event = threading.Event()

    def handle_sig(sig, frame):
        typer.secho("\nStopping Fleet Scheduler daemon...", fg=typer.colors.YELLOW)
        sched.stop()
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sig)
    signal.signal(signal.SIGTERM, handle_sig)

    sched.start()

    while not stop_event.is_set():
        try:
            time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            break

    typer.secho("Daemon stopped.", fg=typer.colors.GREEN)


@cyber_app.command("gate")
def cyber_gate(
    target: str = typer.Argument(..., help="Target to audit as a CI/CD gate"),
    min_grade: str = typer.Option("B", "--min-grade", help="Fail if posture grade is worse than this (A-F)"),
):
    """CI/CD gate: audit a target and exit non-zero if its grade is below the threshold."""
    adapter = CyberAnalysisAdapter()
    report = adapter.analyze_target(target)
    posture = score_findings(report.findings)

    grades = ["A", "B", "C", "D", "F"]
    threshold = min_grade.upper()
    if threshold not in grades:
        typer.secho(f"Invalid --min-grade '{min_grade}'. Use one of {grades}.", fg=typer.colors.RED)
        raise typer.Exit(code=2)

    passed = grades.index(posture.grade) <= grades.index(threshold)
    color = typer.colors.GREEN if passed else typer.colors.RED
    typer.secho(f"{target}: {posture.score}/100 grade {posture.grade} (min {threshold})", fg=color, bold=True)
    if not passed:
        typer.secho("GATE FAILED", fg=typer.colors.RED, bold=True)
        raise typer.Exit(code=1)
    typer.secho("GATE PASSED", fg=typer.colors.GREEN, bold=True)


@user_app.command("create")
def user_create(
    username: str = typer.Argument(..., help="Username"),
    role: str = typer.Option("viewer", help="admin | auditor | viewer"),
    tenant: str = typer.Option("default", help="Tenant the user belongs to"),
    password: str = typer.Option(..., prompt=True, hide_input=True, confirmation_prompt=True, help="Password"),
):
    """Create or update a user account."""
    try:
        user = auth.create_user(username, password, role=role, tenant=tenant)
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED)
        raise typer.Exit(code=2) from exc
    typer.secho(f"User '{user.username}' created (role={user.role}, tenant={user.tenant}).", fg=typer.colors.GREEN)


@user_app.command("list")
def user_list():
    """List user accounts."""
    users = auth.list_users()
    if not users:
        typer.secho("No users. Create one with 'user create'.", fg=typer.colors.YELLOW)
        return
    for u in users:
        typer.echo(f"  {u.username}  role={u.role}  tenant={u.tenant}")


if __name__ == "__main__":
    app()
