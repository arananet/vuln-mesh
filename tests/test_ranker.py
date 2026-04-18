import pytest
from pathlib import Path

from vuln_mesh.ingestion.loader import ingest, FileNode, FileGraph
from vuln_mesh.ranker.scorer import rank, _unsafe_density


FIXTURES = Path(__file__).parent / "fixtures" / "simple"


def _make_graph(files: dict[str, str]) -> FileGraph:
    nodes = [
        FileNode(path=p, language="c", content=c, size_bytes=len(c))
        for p, c in files.items()
    ]
    return FileGraph(nodes=nodes)


def test_rank_returns_all_nodes():
    graph = ingest(str(FIXTURES))
    results = rank(graph)
    assert len(results) == len(graph.nodes)


def test_rank_sorted_descending():
    graph = ingest(str(FIXTURES))
    results = rank(graph)
    scores = [r.score for r in results]
    assert scores == sorted(scores, reverse=True)


def test_rank_scores_in_range():
    graph = ingest(str(FIXTURES))
    for r in rank(graph):
        assert 0.0 <= r.score <= 1.0


def test_rank_top_n():
    graph = ingest(str(FIXTURES))
    results = rank(graph, top_n=1)
    assert len(results) == 1


def test_rank_min_score():
    graph = ingest(str(FIXTURES))
    results = rank(graph, min_score=0.99)
    for r in results:
        assert r.score >= 0.99


def test_rank_empty_graph():
    graph = FileGraph()
    assert rank(graph) == []


def test_unsafe_file_ranks_higher():
    unsafe = "void f() { char b[8]; strcpy(b, gets(b)); sprintf(b, \"%s\", b); }"
    safe = "int add(int a, int b) { return a + b; }"
    graph = _make_graph({"unsafe.c": unsafe, "safe.c": safe})
    results = rank(graph)
    unsafe_r = next(r for r in results if "unsafe" in r.node.path)
    safe_r = next(r for r in results if "safe" in r.node.path)
    assert unsafe_r.score >= safe_r.score


def test_unsafe_density_counts_calls():
    src = "strcpy(a,b); gets(b); sprintf(c,d,e);\n\n"
    density = _unsafe_density(FileNode("x.c", "c", src, size_bytes=len(src)))
    assert density > 0
