import math

WEIGHTS = {"criticality": 0.30, "sensitivity": 0.20, "escalation": 0.20, "exploitability": 0.20, "simplicity": 0.10}
TOXIC_BONUS = 3


def severity(score: int) -> str:
    return "CRITICAL" if score >= 85 else "HIGH" if score >= 65 else "MEDIUM" if score >= 40 else "LOW"


def _level(x: float) -> str:
    return "CRITICAL" if x >= 0.8 else "HIGH" if x >= 0.6 else "MEDIUM" if x >= 0.4 else "LOW"


def score_path(G, path, rules) -> dict:
    edges = [G[u][v] for u, v in zip(path, path[1:])]
    hops = len(edges)
    privs = [e["privilege"] for e in edges]
    parts = {
        "criticality": G.nodes[path[-1]].get("criticality", 5) / 10,          # value of the target asset
        "sensitivity": sum(e["sensitivity"] for e in edges) / hops,           # average permission sensitivity
        "escalation": max(0.0, min(1.0, (max(privs) - privs[0]) / 4)),        # low-privilege start -> high-privilege end
        "exploitability": math.prod(e["exploitability"] for e in edges) ** (1 / hops),  # geometric mean per hop
        "simplicity": 1 / (1 + 0.15 * (hops - 1)),                             # fewer hops = easier
    }
    base = 100 * sum(WEIGHTS[k] * v for k, v in parts.items())
    score = min(100, round(base + (TOXIC_BONUS if rules else 0)))
    return {"score": score, "severity": severity(score), "hops": hops,
            "breakdown": {k: {"value": round(v, 2), "level": _level(v)} for k, v in parts.items()},
            "path_probability": round(math.prod(e["exploitability"] for e in edges), 3)}
