from pathlib import Path

import pytest
import yaml

from augur.invariants.loader import Invariant, load


def _write(tmp_path: Path, doc) -> Path:
    p = tmp_path / "inv.yaml"
    p.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return p


def test_parses_valid(tmp_path: Path):
    p = _write(
        tmp_path,
        {
            "invariants": [
                {
                    "name": "no-leak",
                    "endpoint": "GET /users/*",
                    "rule": "must not leak",
                    "severity": "high",
                }
            ]
        },
    )
    invs = load(p)
    assert len(invs) == 1
    assert invs[0].name == "no-leak"
    assert invs[0].method == "GET"


def test_rejects_bad_root(tmp_path: Path):
    p = _write(tmp_path, {"invariants": "not-a-list"})
    with pytest.raises(ValueError):
        load(p)


def test_rejects_bad_item(tmp_path: Path):
    p = _write(tmp_path, {"invariants": [42]})
    with pytest.raises(ValueError):
        load(p)


def test_rejects_bad_severity(tmp_path: Path):
    p = _write(
        tmp_path,
        {
            "invariants": [
                {
                    "name": "x",
                    "endpoint": "GET /a",
                    "rule": "r",
                    "severity": "boom",
                }
            ]
        },
    )
    with pytest.raises(ValueError):
        load(p)


def test_rejects_bad_endpoint_format(tmp_path: Path):
    p = _write(
        tmp_path,
        {"invariants": [{"name": "x", "endpoint": "garbage", "rule": "r"}]},
    )
    with pytest.raises(ValueError):
        load(p)


def test_matches_method_and_path():
    inv = Invariant(name="n", method="GET", path_pattern="/users/*", rule="r", severity="low")
    assert inv.matches("GET", "/users/42")
    assert not inv.matches("POST", "/users/42")
    assert not inv.matches("GET", "/users/42/posts")  # * is one segment


def test_matches_wildcard_method():
    inv = Invariant(name="n", method="*", path_pattern="/x", rule="r", severity="low")
    assert inv.matches("GET", "/x")
    assert inv.matches("DELETE", "/x")
