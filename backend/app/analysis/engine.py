import hashlib
from ..config import settings
from ..graph.builder import traversable_copy
from ..explain.explainer import explain_path
from . import toxic
from .pathfinder import find_paths, reachable_assets_bfs
from .risk import score_path


def _record(G, path):
    tags = toxic.path_tags(G, path)
    rules = toxic.match_rules(tags)
    rec = {"id": hashlib.sha1("|".join(path).encode()).hexdigest()[:10],
           "entry": path[0], "target": path[-1],
           "nodes": [{"id": n, "name": G.nodes[n]["name"], "type": G.nodes[n]["type"]} for n in path],
           "tags": sorted(tags), "toxic_rules": rules}
    rec.update(score_path(G, path, rules))
    rec["explanation"] = explain_path(G, path, rec)
    return rec


def analyze(G, k=3):
    T = traversable_copy(G)
    thr = settings.CRITICAL_THRESHOLD
    entries = [n for n, d in G.nodes(data=True) if d["type"] == "GitHubUser"]
    assets = [n for n, d in G.nodes(data=True) if d["type"] == "Resource" and d.get("criticality", 0) >= thr]
    records = [_record(G, p) for e in entries for a in assets for p in find_paths(G, T, e, a, k)]
    records.sort(key=lambda r: -r["score"])
    entry_points = []
    for e in entries:
        mine = [r for r in records if r["entry"] == e]
        entry_points.append({"id": e, "name": G.nodes[e]["name"],
                             "potential_critical_assets": len(reachable_assets_bfs(T, e, thr)),
                             "confirmed_paths": len(mine), "top_score": max((r["score"] for r in mine), default=0)})
    return {"paths": records, "toxic": toxic.summarize(records), "entry_points": sorted(entry_points, key=lambda x: -x["top_score"])}
