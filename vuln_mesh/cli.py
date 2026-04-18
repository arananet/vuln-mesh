from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import click
import yaml

from vuln_mesh.adapters.base import AdapterConfig
from vuln_mesh.adapters.factory import build_adapter
from vuln_mesh.agents.mesh import run_mesh
from vuln_mesh.ingestion.loader import ingest
from vuln_mesh.oracle.runner import OracleStatus, run_oracle
from vuln_mesh.ranker.scorer import rank
from vuln_mesh.report.markdown import render_markdown

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


@click.command()
@click.option("--config", "-c", default="config/default.yaml", help="Config YAML path")
@click.option("--source", "-s", help="Override target.source from config")
@click.option("--output", "-o", default=None, help="Output report path")
@click.option("--top-n", default=None, type=int, help="Override ranker.top_n")
def main(config: str, source: str | None, output: str | None, top_n: int | None) -> None:
    """vuln-mesh: LLM-powered vulnerability discovery pipeline."""
    cfg = _load_config(config)

    src = source or cfg["target"]["source"]
    _top_n = top_n or cfg["ranker"].get("top_n")
    min_score = cfg["ranker"].get("min_score", 0.0)
    concurrency = cfg["agents"].get("concurrency", 32)
    hunt_profile = cfg["agents"].get("model_profile", "triage")
    verify_profile = cfg["agents"].get("verifier_profile", hunt_profile)

    log.info("Ingesting %s", src)
    graph = ingest(src)
    log.info("Found %d C/C++ files", len(graph.nodes))

    ranked = rank(graph, top_n=_top_n, min_score=min_score)
    log.info("Ranked %d files for analysis", len(ranked))

    hunt_adapter = _make_adapter(cfg, hunt_profile)
    verifier_adapter = _make_adapter(cfg, verify_profile)

    log.info("Running agent mesh (concurrency=%d)", concurrency)
    verified = asyncio.run(run_mesh(ranked, hunt_adapter, verifier_adapter, concurrency))
    log.info("Agent mesh: %d verified findings", len(verified))

    log.info("Running oracle verification")
    oracle_results = []
    for vf in verified:
        result = run_oracle(vf)
        if result.status == OracleStatus.CRASHED:
            log.info("CONFIRMED: %s in %s", vf.finding.bug_class, vf.finding.file_path)
            oracle_results.append(result)
        else:
            log.info("Oracle filtered out %s (%s)", vf.finding.bug_class, result.status)

    log.info("Confirmed crash-reproduced findings: %d", len(oracle_results))

    report_cfg = cfg.get("report", {})
    cvss = report_cfg.get("cvss_estimate", True)
    report = render_markdown(oracle_results, output_path=output, cvss_estimate=cvss)

    out_path = output or "vuln-mesh-report-*.md"
    click.echo(f"\nReport written to {out_path}")
    click.echo(f"Total confirmed findings: {len(oracle_results)}")


if __name__ == "__main__":
    main()
