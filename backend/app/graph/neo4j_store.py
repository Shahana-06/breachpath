"""Optional persistence of the graph in Neo4j so you can explore it with Cypher / Neo4j Browser."""
from ..config import settings
from ..schema import NODE_TYPES, REL_DEFAULTS


def _clean(props: dict) -> dict:
    out = {}
    for k, v in props.items():
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
        elif isinstance(v, list) and all(isinstance(i, (str, int, float, bool)) for i in v):
            out[k] = v
    return out


def sync_to_neo4j(G):
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(settings.NEO4J_URI, auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD))
    with driver.session() as s:
        s.run("MATCH (n:BPNode) DETACH DELETE n")
        for ntype in NODE_TYPES:  # labels cannot be parameterised -> whitelist
            rows = [{"id": n, "props": _clean(d)} for n, d in G.nodes(data=True) if d["type"] == ntype]
            if rows:
                s.run(f"UNWIND $rows AS r MERGE (n:BPNode {{id: r.id}}) SET n:`{ntype}`, n += r.props", rows=rows)
        for rel in REL_DEFAULTS:
            rows = [{"a": u, "b": v, "props": _clean(d)} for u, v, d in G.edges(data=True) if d["rel"] == rel]
            if rows:
                s.run(f"UNWIND $rows AS r MATCH (a:BPNode {{id:r.a}}), (b:BPNode {{id:r.b}}) "
                      f"MERGE (a)-[e:`{rel}`]->(b) SET e += r.props", rows=rows)
    driver.close()
