from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .analysis.engine import analyze
from .collectors.aws_collector import AWSCollector
from .collectors.github_collector import GitHubCollector
from .collectors.mock_data import get_mock
from .collectors.normalize import normalize
from .config import settings
from .explain.explainer import llm_explain
from .graph.builder import build_graph

STATE = {"graph": None, "result": None, "source": None, "scanned_at": None, "warnings": []}


def run_scan(source: str, sync_neo4j: bool = False):
    warnings = []
    if source == "mock":
        gh, aws = get_mock()
    else:
        if not settings.GITHUB_TOKEN or not settings.GITHUB_ORG:
            raise HTTPException(400, "Set GITHUB_TOKEN and GITHUB_ORG in .env to run a live scan.")
        gh = GitHubCollector(settings.GITHUB_TOKEN, settings.GITHUB_ORG).collect()
        warnings += gh.get("warnings", [])
        aws = AWSCollector(settings.AWS_PROFILE, settings.AWS_REGION).collect()
    G = build_graph(normalize(gh, aws))
    STATE.update(graph=G, result=analyze(G), source=source, warnings=warnings,
                 scanned_at=datetime.now(timezone.utc).isoformat())
    if sync_neo4j and settings.NEO4J_URI:
        from .graph.neo4j_store import sync_to_neo4j
        sync_to_neo4j(G)


@asynccontextmanager
async def lifespan(app):
    run_scan("mock")
    yield


app = FastAPI(title="BreachPath CI/CD", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class ScanRequest(BaseModel):
    source: Literal["mock", "live"] = "mock"
    sync_neo4j: bool = False


def _need():
    if not STATE["result"]:
        raise HTTPException(409, "No scan yet. POST /api/scan first.")
    return STATE["result"]


@app.post("/api/scan")
def scan(req: ScanRequest):
    run_scan(req.source, req.sync_neo4j)
    return {"ok": True, "source": STATE["source"], "paths": len(STATE["result"]["paths"]), "warnings": STATE["warnings"]}


@app.get("/api/summary")
def summary():
    res, G = _need(), STATE["graph"]
    sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for p in res["paths"]:
        sev[p["severity"]] += 1
    count = lambda *t: sum(1 for _, d in G.nodes(data=True) if d["type"] in t)
    return {"source": STATE["source"], "scanned_at": STATE["scanned_at"], "severity": sev,
            "total_paths": len(res["paths"]), "top_score": res["paths"][0]["score"] if res["paths"] else 0,
            "total_assets": count("Repository", "Workflow", "Secret", "Resource"),
            "total_identities": count("GitHubUser", "GitHubTeam", "IAMUser", "IAMRole"),
            "neo4j_enabled": bool(settings.NEO4J_URI), "llm_enabled": bool(settings.ANTHROPIC_API_KEY)}


@app.get("/api/paths")
def paths(entry: str | None = None, severity: str | None = None, limit: int = Query(50, le=500)):
    out = _need()["paths"]
    if entry:
        out = [p for p in out if p["entry"] == entry or p["nodes"][0]["name"] == entry]
    if severity:
        out = [p for p in out if p["severity"] == severity.upper()]
    return out[:limit]


@app.get("/api/paths/{pid}")
def path_detail(pid: str, llm: bool = False):
    rec = next((p for p in _need()["paths"] if p["id"] == pid), None)
    if not rec:
        raise HTTPException(404, "Unknown path id")
    if llm and "llm_text" not in rec["explanation"]:
        rec["explanation"]["llm_text"] = llm_explain(rec)
    return rec


@app.get("/api/toxic")
def toxic_view():
    return _need()["toxic"]


@app.get("/api/entry-points")
def entry_points():
    return _need()["entry_points"]


@app.get("/api/graph")
def graph():
    _need()
    G = STATE["graph"]
    return {"nodes": [{"id": n, "name": d["name"], "type": d["type"], "criticality": d.get("criticality")}
                      for n, d in G.nodes(data=True)],
            "edges": [{"source": u, "target": v, "rel": d["rel"]} for u, v, d in G.edges(data=True)]}
