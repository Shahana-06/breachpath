from app.analysis.engine import analyze
from app.analysis.pathfinder import is_valid_path
from app.collectors.mock_data import get_mock
from app.collectors.normalize import normalize
from app.graph.builder import build_graph


def _run():
    G = build_graph(normalize(*get_mock()))
    return G, analyze(G)


def _has(res, entry, target):
    return any(p["nodes"][0]["name"] == entry and p["nodes"][-1]["name"] == target for p in res["paths"])


def test_workflow_takeover_found():
    _, res = _run()
    assert _has(res, "dev-user", "prod-database")


def test_leaked_key_pivot_found_for_read_only_intern():
    _, res = _run()
    path = next(p for p in res["paths"] if p["nodes"][0]["name"] == "intern-user" and p["nodes"][-1]["name"] == "prod-database")
    types = [n["type"] for n in path["nodes"]]
    assert "Secret" in types and "Resource" in types and "TOX-002" in path["toxic_rules"]


def test_read_only_user_cannot_use_workflow():
    G, _ = _run()
    bad = ["gh:user:intern-user", "gh:repo:acme/payment-service", "gh:wf:acme/payment-service:.github/workflows/deploy.yml",
           "aws:role:DeployRole", "aws:policy:DeployPolicy", "aws:res:rds:prod-database"]
    assert not is_valid_path(G, bad)


def test_no_false_positives():
    _, res = _run()
    assert not _has(res, "viewer-bob", "prod-database")
    assert not _has(res, "alice", "prod-database")


def test_team_path_and_wildcard_toxic_rule():
    _, res = _run()
    carol = [p for p in res["paths"] if p["nodes"][0]["name"] == "carol"]
    assert carol and any("TOX-003" in p["toxic_rules"] for p in carol)


def test_scores_bounded_and_sorted():
    _, res = _run()
    scores = [p["score"] for p in res["paths"]]
    assert scores == sorted(scores, reverse=True) and all(0 <= s <= 100 for s in scores)
