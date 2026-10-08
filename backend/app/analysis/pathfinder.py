import networkx as nx


def is_valid_path(G, path) -> bool:
    """Semantic checks a plain graph search cannot express:
    - editing a workflow needs WRITE on the repo (read-only users cannot)
    - reading a secret in a repo needs at least READ."""
    prev = None
    for u, v in zip(path, path[1:]):
        rel = G[u][v]["rel"]
        if rel == "HAS_WORKFLOW" and prev != "CAN_WRITE":
            return False
        if rel == "CONTAINS_SECRET" and prev not in ("CAN_READ", "CAN_WRITE"):
            return False
        prev = rel
    return True


def find_paths(G, T, source, target, k=3, max_hops=9, max_candidates=80):
    """Top-k loop-free paths by attacker cost (Dijkstra-weighted, Yen's algorithm), filtered for validity."""
    found = []
    try:
        for i, p in enumerate(nx.shortest_simple_paths(T, source, target, weight="cost")):
            if i >= max_candidates or len(p) - 1 > max_hops:
                break
            if is_valid_path(G, p):
                found.append(p)
                if len(found) >= k:
                    break
    except (nx.NetworkXNoPath, nx.NodeNotFound):
        pass
    return found


def reachable_assets_bfs(T, source, threshold):
    """BFS blast-radius upper bound (ignores validity rules) - used for the entry-point overview."""
    return [n for n in nx.descendants(T, source)
            if T.nodes[n]["type"] == "Resource" and T.nodes[n].get("criticality", 0) >= threshold]
