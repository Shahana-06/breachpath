"""Normalization & relationship extraction: stitches GitHub + AWS datasets into one cross-platform dataset.
Creates the edges neither collector can see alone: Secret->IAMUser, Workflow->IAMRole (via OIDC trust), principal->Role."""
import fnmatch
from ..schema import make_edge

OIDC_ID = "aws:oidc:github"


def sub_exploitability(pattern: str):
    """How easy is it to satisfy this OIDC `sub` pattern? Returns (probability, is_wildcard)."""
    parts = pattern.split(":")
    repo_part = parts[1] if len(parts) > 1 else "*"
    if "*" in repo_part:
        return 0.95, True            # wildcard on org/repo -> many repos can assume
    if pattern.endswith(":*"):
        return 0.85, False           # any branch/PR of one repo
    if ":environment:" in pattern:
        return 0.45, False           # protected environment
    return 0.70, False               # pinned to a branch (needs push to that branch)


def _candidate_subs(repo_node):
    full = repo_node["full_name"]
    br = repo_node.get("default_branch", "main")
    return [f"repo:{full}:ref:refs/heads/{br}", f"repo:{full}:pull_request", f"repo:{full}:environment:production"]


def link_oidc(nodes, edges):
    repos = {n["full_name"]: n for n in nodes.values() if n["type"] == "Repository"}
    roles = [n for n in nodes.values() if n["type"] == "IAMRole" and (n.get("oidc_subs") or n.get("oidc_missing_sub"))]
    if not roles:
        return
    nodes.setdefault(OIDC_ID, {"id": OIDC_ID, "type": "OIDCProvider", "name": "github-oidc"})
    for wf in [n for n in nodes.values() if n["type"] == "Workflow"]:
        repo = repos.get(wf["repo"])
        if not repo:
            continue
        trusted = False
        for role in roles:
            best, wildcard, no_sub = 0.0, False, False
            if role.get("oidc_missing_sub"):
                best, wildcard, no_sub = 1.0, True, True
            for pat in role.get("oidc_subs", []):
                if any(fnmatch.fnmatchcase(c, pat) for c in _candidate_subs(repo)):
                    p, w = sub_exploitability(pat)
                    if p > best:
                        best, wildcard = p, w
            if best == 0:
                continue
            declared = role.get("arn") in wf.get("declared_roles", [])
            edges.append(make_edge(wf["id"], role["id"], "CAN_ASSUME",
                                   exploitability=round(best if declared else best * 0.85, 3),
                                   wildcard=wildcard, no_sub=no_sub, declared=declared))
            trusted = True
        if trusted:
            edges.append(make_edge(OIDC_ID, wf["id"], "TRUSTS"))


def link_secrets(nodes, edges):
    key_owner = {k: n["id"] for n in nodes.values() if n["type"] == "IAMUser" for k in n.get("access_key_ids", [])}
    for n in nodes.values():
        if n["type"] == "Secret" and n.get("access_key_id") in key_owner:
            edges.append(make_edge(n["id"], key_owner[n["access_key_id"]], "GRANTS_CREDENTIALS"))


def link_principals(nodes, edges):
    by_arn = {n["arn"]: n["id"] for n in nodes.values() if n.get("arn")}
    for role in [n for n in nodes.values() if n["type"] == "IAMRole"]:
        for arn in role.get("trusted_principals", []):
            if arn in by_arn and by_arn[arn] != role["id"]:
                edges.append(make_edge(by_arn[arn], role["id"], "CAN_ASSUME", exploitability=0.8))


def normalize(gh: dict, aws: dict) -> dict:
    nodes = {n["id"]: n for n in gh["nodes"] + aws["nodes"]}
    edges = list(gh["edges"]) + list(aws["edges"])
    link_secrets(nodes, edges)
    link_oidc(nodes, edges)
    link_principals(nodes, edges)
    return {"nodes": list(nodes.values()), "edges": edges}
