"""Ground-truth evaluation: precision / recall / runtime on the demo scenario.
Extend GROUND_TRUTH with the attack scenarios you build in your own lab (BloodHound / Pacu validated)."""
import time
from app.analysis.engine import analyze
from app.collectors.mock_data import get_mock
from app.collectors.normalize import normalize
from app.graph.builder import build_graph

# (entry user, critical target) -> should an attack path exist?
GROUND_TRUTH = {
    ("dev-user", "prod-database"): True, ("intern-user", "prod-database"): True,
    ("carol", "prod-database"): True, ("carol", "customer-backups"): True,
    ("alice", "prod-database"): False, ("viewer-bob", "prod-database"): False,
    ("viewer-bob", "customer-backups"): False, ("alice", "customer-backups"): False,
    ("dev-user", "customer-backups"): False, ("intern-user", "customer-backups"): False,
}

t = time.perf_counter()
G = build_graph(normalize(*get_mock()))
res = analyze(G)
elapsed = time.perf_counter() - t
found = {(p["nodes"][0]["name"], p["nodes"][-1]["name"]) for p in res["paths"]}
tp = sum(1 for k, v in GROUND_TRUTH.items() if v and k in found)
fp = sum(1 for k, v in GROUND_TRUTH.items() if not v and k in found)
fn = sum(1 for k, v in GROUND_TRUTH.items() if v and k not in found)
precision = tp / (tp + fp) if tp + fp else 1.0
recall = tp / (tp + fn) if tp + fn else 1.0
print(f"TP={tp} FP={fp} FN={fn}  precision={precision:.2f} recall={recall:.2f}  time={elapsed*1000:.0f} ms")
print("toxic share:", res["toxic"]["quantification"])
