import pytest
from pathlib import Path

from vuln_mesh.ingestion.loader import ingest, _parse_includes, _detect_entry_point, IngestionError

FIXTURES = Path(__file__).parent / "fixtures" / "simple"


def test_ingest_finds_c_files():
    graph = ingest(str(FIXTURES))
    paths = [n.path for n in graph.nodes]
    assert any("main.c" in p for p in paths)
    assert any("utils.c" in p for p in paths)


def test_ingest_detects_entry_point():
    graph = ingest(str(FIXTURES))
    entry_nodes = [n for n in graph.nodes if n.is_entry_point]
    assert len(entry_nodes) >= 1
    assert any("main.c" in n.path for n in entry_nodes)


def test_ingest_non_entry_point():
    graph = ingest(str(FIXTURES))
    utils = next(n for n in graph.nodes if "utils.c" in n.path)
    assert utils.is_entry_point is False


def test_ingest_dependency_edges():
    graph = ingest(str(FIXTURES))
    # main.c includes utils.h → expect an edge
    assert len(graph.edges) > 0


def test_ingest_missing_path_raises():
    with pytest.raises(IngestionError):
        ingest("/nonexistent/path/abc123")


def test_ingest_empty_dir(tmp_path):
    graph = ingest(str(tmp_path))
    assert graph.nodes == []
    assert graph.edges == []


def test_parse_includes():
    src = '#include <stdio.h>\n#include "utils.h"\n'
    includes = _parse_includes(src)
    assert "stdio.h" in includes
    assert "utils.h" in includes


def test_detect_entry_point_positive():
    assert _detect_entry_point("int main(int argc, char *argv[]) { }") is True


def test_detect_entry_point_negative():
    assert _detect_entry_point("void helper(void) { }") is False
