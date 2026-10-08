"""Toxic permission combinations: permissions that look harmless alone but are dangerous together.
1) Tag every attack path with the capabilities it uses.  2) Match named rules.  3) Mine frequent combos (support / lift)."""
import math
from collections import Counter
from itertools import combinations
from ..config import settings

REL_TAG = {"CAN_READ": "repo_read", "CAN_WRITE": "repo_write", "MEMBER_OF": "team_membership",
           "HAS_WORKFLOW": "workflow_modify", "CONTAINS_SECRET": "secret_exposure", "GRANTS_CREDENTIALS": "credential_use",
           "CAN_ASSUME": "role_assumption", "HAS_POLICY": "policy_attached", "CAN_ACCESS": "resource_access",
           "EXECUTES_AS": "compute_pivot"}

RULES = [
    {"id": "TOX-001", "name": "Workflow takeover to critical asset",
     "requires": {"repo_write", "workflow_modify", "role_assumption", "critical_access"},
     "description": "Write access to a repo lets an attacker edit a workflow that can assume an IAM role reaching a critical asset."},
    {"id": "TOX-002", "name": "Leaked cloud key to critical asset",
     "requires": {"repo_read", "secret_exposure", "credential_use", "critical_access"},
     "description": "Read access to a repo exposes an AWS key whose permissions chain to a critical asset."},
    {"id": "TOX-003", "name": "Wildcard OIDC trust with admin policy",
     "requires": {"wildcard_trust", "admin_policy"},
     "description": "An OIDC trust policy that matches many repos is attached to a role with administrator permissions."},
    {"id": "TOX-004", "name": "Code-execution pivot",
     "requires": {"compute_pivot", "critical_access", "credential_use"},
     "description": "A credential can change Lambda code, which then runs with a role that reaches a critical asset."},
]


def path_tags(G, path) -> set:
    tags = set()
    for u, v in zip(path, path[1:]):
        e = G[u][v]
        tags.add(REL_TAG[e["rel"]])
        if e.get("wildcard"):
            tags.add("wildcard_trust")
        if e.get("admin"):
            tags.add("admin_policy")
        if e["rel"] == "CAN_ACCESS" and G.nodes[v].get("criticality", 0) >= settings.CRITICAL_THRESHOLD:
            tags.add("critical_access")
    if "repo_write" in tags:
        tags.add("repo_read")   # write implies read
    return tags


def match_rules(tags: set) -> list:
    return [r["id"] for r in RULES if r["requires"] <= tags]


def summarize(records: list) -> dict:
    n = len(records)
    alerts = []
    for rule in RULES:
        hit = [r for r in records if rule["id"] in r["toxic_rules"]]
        alerts.append({"id": rule["id"], "name": rule["name"], "description": rule["description"],
                       "count": len(hit), "path_ids": [h["id"] for h in hit][:10]})
    toxic = sum(1 for r in records if r["toxic_rules"])
    combos = []
    if n:
        tagsets = [set(r["tags"]) for r in records]
        singles = Counter(t for s in tagsets for t in s)
        for size in (2, 3):
            for combo in combinations(sorted(singles), size):
                sup = sum(1 for s in tagsets if set(combo) <= s) / n
                if sup < 0.2:
                    continue
                lift = sup / math.prod(singles[t] / n for t in combo)
                combos.append({"combo": list(combo), "support": round(sup, 2), "lift": round(lift, 2)})
        combos.sort(key=lambda c: (-c["lift"], -c["support"]))
    return {"alerts": alerts,
            "quantification": {"total_paths": n, "toxic_combo_paths": toxic, "single_misconfig_paths": n - toxic,
                               "toxic_share_pct": round(100 * toxic / n, 1) if n else 0.0},
            "frequent_combinations": combos[:10]}
