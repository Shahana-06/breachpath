import networkx as nx
from ..schema import edge_cost


def build_graph(dataset: dict) -> nx.DiGraph:
    """Typed property graph. One edge per (src,dst); the higher-privilege relationship wins."""
    G = nx.DiGraph()
    for n in dataset["nodes"]:
        G.add_node(n["id"], **{k: v for k, v in n.items() if k != "id"})
    for e in dataset["edges"]:
        if e["src"] not in G or e["dst"] not in G:
            continue
        e = dict(e)
        e["cost"] = edge_cost(e)
        old = G.get_edge_data(e["src"], e["dst"])
        if old and old["privilege"] >= e["privilege"]:
            continue
        G.add_edge(e["src"], e["dst"], **{k: v for k, v in e.items() if k not in ("src", "dst")})
    return G


def traversable_copy(G: nx.DiGraph) -> nx.DiGraph:
    T = nx.DiGraph()
    T.add_nodes_from(G.nodes(data=True))
    T.add_edges_from((u, v, d) for u, v, d in G.edges(data=True) if d.get("traversable", True))
    return T
