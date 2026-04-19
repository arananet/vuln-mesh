from __future__ import annotations

import asyncio
import logging
from typing import Any

import click
import yaml

from vuln_mesh.adapters.base import AdapterConfig
from vuln_mesh.adapters.factory import build_adapter
from vuln_mesh.agents.mesh import run_mesh
from vuln_mesh.dashboard.state import EventType, PipelineEvent, PipelineTracker
from vuln_mesh.db.repository import ScanRepository
from vuln_mesh.db.session import get_session_factory
from vuln_mesh.ingestion.loader import ingest
from vuln_mesh.oracle.runner import OracleStatus, run_oracle
from vuln_mesh.ranker.scorer import rank
from vuln_mesh.report.markdown import finding_hash, render_markdown

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("vuln_mesh.cli")


def _load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def _make_adapter(cfg: dict, profile: str):
    adapters = cfg.get("adapters", {})
    p = adapters.get(profile, {})
    return build_adapter(AdapterConfig(
        provider=p.get("provider", "anthropic"),
        model=p.get("model", "claude-sonnet-4-6"),
        base_url=p.get("base_url", ""),
        api_key=p.get("api_key", ""),
    ))


async def _persist_results(src: str, oracle_results: list, stats: dict) -> None:
    """Write scan run and findings to the database if DATABASE_URL is set."""
    factory = get_session_factory()
    if not factory:
        return
    async with factory() as session:
        repo = ScanRepository(session)
        scan = await repo.create_scan(src)
        for result in oracle_results:
            f = result.finding.finding
            await repo.add_finding(
                scan_id=scan.id,
                file_path=f.file_path,
                line_hint=f.line_hint,
                bug_class=f.bug_class,
                description=f.description,
                exploit_input=f.exploit_input,
                verifier_rationale=result.finding.verifier_rationale,
                oracle_output=result.output,
                finding_hash=finding_hash(f.file_path, f.exploit_input),
            )
        await repo.complete_scan(
            scan.id,
            files_ingested=stats.get("files_ingested", 0),
            files_ranked=stats.get("files_ranked", 0),
            findings_confirmed=len(oracle_results),
        )
        log.info("Scan persisted to database (id=%s)", scan.id)


async def _run_scan(
    cfg: dict,
    src: str,
    top_n: int | None,
    output: str | None,
    tracker: PipelineTracker | None,
) -> None:
    min_score = cfg["ranker"].get("min_score", 0.0)
    concurrency = cfg["agents"].get("concurrency", 32)
    hunt_profile = cfg["agents"].get("model_profile", "triage")
    verify_profile = cfg["agents"].get("verifier_profile", hunt_profile)

    async def _emit(t: EventType, data: dict) -> None:
        if tracker:
            await tracker.emit(PipelineEvent(t, data))

    await _emit(EventType.SCAN_STARTED, {"target": src})

    log.info("Ingesting %s", src)
    graph = ingest(src)
    log.info("Found %d source files", len(graph.nodes))
    await _emit(EventType.INGESTION_COMPLETE, {"count": len(graph.nodes)})

    ranked = rank(graph, top_n=top_n, min_score=min_score)
    log.info("Ranked %d files for analysis", len(ranked))
    await _emit(EventType.RANKING_COMPLETE, {"count": len(ranked)})

    hunt_adapter = _make_adapter(cfg, hunt_profile)
    verifier_adapter = _make_adapter(cfg, verify_profile)

    log.info("Running agent mesh (concurrency=%d)", concurrency)
    verified = await run_mesh(ranked, hunt_adapter, verifier_adapter, concurrency, tracker)
    log.info("Agent mesh: %d verified findings", len(verified))

    log.info("Running oracle verification")
    oracle_results = []
    for vf in verified:
        result = run_oracle(vf)
        status_str = result.status.value
        await _emit(EventType.ORACLE_RESULT, {
            "path": vf.finding.file_path,
            "bug_class": vf.finding.bug_class,
            "status": status_str,
            "output_excerpt": result.output[:512],
        })
        if result.status == OracleStatus.CRASHED:
            log.info("CONFIRMED: %s in %s", vf.finding.bug_class, vf.finding.file_path)
            oracle_results.append(result)
        else:
            log.info("Oracle filtered out %s (%s)", vf.finding.bug_class, result.status)

    log.info("Confirmed crash-reproduced findings: %d", len(oracle_results))

    report_cfg = cfg.get("report", {})
    cvss = report_cfg.get("cvss_estimate", True)
    render_markdown(oracle_results, output_path=output, cvss_estimate=cvss)

    stats = tracker.stats if tracker else {
        "files_ingested": len(graph.nodes),
        "files_ranked": len(ranked),
    }
    await _persist_results(src, oracle_results, stats)

    await _emit(EventType.SCAN_COMPLETE, {
        "confirmed": len(oracle_results),
        "report_path": output or "vuln-mesh-report-*.md",
    })


@click.command()
@click.option("--config", "-c", default="config/default.yaml", help="Config YAML path")
@click.option("--source", "-s", help="Override target.source from config")
@click.option("--output", "-o", default=None, help="Output report path")
@click.option("--top-n", default=None, type=int, help="Override ranker.top_n")
@click.option("--dashboard/--no-dashboard", default=False, help="Start web dashboard")
@click.option("--port", default=7654, show_default=True, help="Dashboard port")
def main(
    config: str,
    source: str | None,
    output: str | None,
    top_n: int | None,
    dashboard: bool,
    port: int,
) -> None:
    """vuln-mesh: LLM-powered vulnerability discovery pipeline."""
    cfg = _load_config(config)
    src = source or cfg["target"]["source"]
    _top_n = top_n or cfg["ranker"].get("top_n")

    if dashboard:
        import uvicorn
        from vuln_mesh.dashboard.app import create_app

        tracker = PipelineTracker()

        def scan_factory():
            return _run_scan(cfg, src, _top_n, output, tracker)

        app = create_app(tracker, scan_factory)
        click.echo(f"Dashboard: http://localhost:{port}")
        uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")
    else:
        asyncio.run(_run_scan(cfg, src, _top_n, output, tracker=None))
        click.echo("Scan complete.")


if __name__ == "__main__":
    main()
