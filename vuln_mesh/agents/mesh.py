from __future__ import annotations

import asyncio
import logging

from vuln_mesh.adapters.base import BaseAdapter
from vuln_mesh.ranker.scorer import RankedFile

from .hunt import HuntAgent
from .verifier import VerifiedFinding, VerifierAgent

log = logging.getLogger(__name__)


async def run_mesh(
    ranked_files: list[RankedFile],
    hunt_adapter: BaseAdapter,
    verifier_adapter: BaseAdapter,
    concurrency: int = 32,
) -> list[VerifiedFinding]:
    sem = asyncio.Semaphore(concurrency)
    hunter = HuntAgent(hunt_adapter)
    verifier = VerifierAgent(verifier_adapter)

    async def _process(ranked: RankedFile) -> list[VerifiedFinding]:
        async with sem:
            findings = await hunter.run(ranked)
            if not findings:
                return []
            results = []
            for finding in findings:
                vf = await verifier.run(finding, ranked.node.content)
                if vf.verified:
                    results.append(vf)
                else:
                    log.info(
                        "Finding discarded by verifier: %s in %s",
                        finding.bug_class,
                        finding.file_path,
                    )
            return results

    tasks = [asyncio.create_task(_process(r)) for r in ranked_files]
    nested = await asyncio.gather(*tasks)
    return [vf for batch in nested for vf in batch]
