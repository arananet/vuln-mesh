import pytest
from unittest.mock import patch, MagicMock
from vuln_mesh.ingestion.git_clone import is_git_url, _inject_token, clone_repo, cleanup


def test_is_git_url_detects_https():
    assert is_git_url("https://github.com/owner/repo")

def test_is_git_url_detects_http():
    assert is_git_url("http://github.com/owner/repo")

def test_is_git_url_detects_git_at():
    assert is_git_url("git@github.com:owner/repo.git")

def test_is_git_url_detects_github_com_prefix():
    assert is_git_url("github.com/owner/repo")

def test_is_git_url_rejects_local_path():
    assert not is_git_url("/path/to/local")

def test_is_git_url_rejects_relative_path():
    assert not is_git_url("./relative/path")


def test_inject_token_rewrites_https():
    result = _inject_token("https://github.com/owner/repo", "mytoken")
    assert result == "https://mytoken@github.com/owner/repo"

def test_inject_token_rewrites_http():
    result = _inject_token("http://github.com/owner/repo", "mytoken")
    assert result == "http://mytoken@github.com/owner/repo"

def test_inject_token_leaves_git_at_unchanged():
    url = "git@github.com:owner/repo.git"
    assert _inject_token(url, "token") == url


def test_clone_repo_raises_on_failure():
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "fatal: repository not found"
    with patch("subprocess.run", return_value=mock_result):
        with pytest.raises(RuntimeError, match="git clone failed"):
            clone_repo("https://github.com/nonexistent/repo")


def test_clone_repo_scrubs_token_from_error():
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stderr = "fatal: could not read from mytoken@github.com"
    with patch("subprocess.run", return_value=mock_result):
        with pytest.raises(RuntimeError) as exc_info:
            clone_repo("https://github.com/x/y", token="mytoken")
    assert "mytoken" not in str(exc_info.value)
    assert "***" in str(exc_info.value)
