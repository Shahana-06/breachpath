# BreachPath CI/CD

Explainable graph-based attack path analysis for GitHub-to-AWS environments.

```
GitHub collector ─┐
                  ├─ normalize (OIDC / secret / principal links) ─ NetworkX graph ─ (optional) Neo4j
AWS collector ────┘                                   │
                                   pathfinding (Yen + Dijkstra) · risk score · toxic combos
                                                      │
                                   explainer (rules, optional LLM) ─ FastAPI ─ React dashboard
```

## 1. Run it (5 minutes, no credentials)
```bash
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m pytest -q            # 6 tests should pass
python evaluate.py             # precision / recall on the demo scenario
uvicorn app.main:app --reload  # API docs: http://localhost:8000/docs
```
```bash
cd frontend && npm install && npm run dev   # http://localhost:5173
```
Full stack with Neo4j: `cp .env.example .env && docker compose up --build` (dashboard on :80, Neo4j Browser on :7474, login neo4j / breachpath123).

## 2. Where each piece lives
| Objective | File |
|---|---|
| Graph builder | `collectors/*`, `collectors/normalize.py`, `graph/builder.py`, `graph/neo4j_store.py` |
| Pathfinding and risk | `analysis/pathfinder.py`, `analysis/risk.py` |
| Toxic combinations | `analysis/toxic.py` |
| Explainable layer | `explain/explainer.py` |
| API / Dashboard | `main.py` / `frontend/src/App.jsx` |
| Evaluation | `tests/`, `evaluate.py` |

## 3. Run it on a real lab (only on accounts you own)
1. Create a throwaway GitHub org with 3-4 repos, a few collaborators/teams, and workflows using `aws-actions/configure-aws-credentials`.
2. Create a separate AWS sandbox account. Add the GitHub OIDC provider (`token.actions.githubusercontent.com`), roles with different `sub` trust conditions (exact branch, `repo:org/repo:*`, `repo:org/*`, none), small policies, one S3 bucket, one RDS or DynamoDB resource named `prod-...`, and one Lambda.
3. Plant a fake AWS access key id (an IAM user's real key id, secret deleted or deactivated) in a test repo file.
4. GitHub token: fine-grained or classic with read access to org members, teams, repo contents and administration (collaborators need admin read). AWS: read-only IAM, S3, RDS and Lambda list permissions.
5. Fill `.env`, click "Scan my GitHub and AWS". Check the warnings list for 403s.

## 4. Neo4j
Set `NEO4J_URI` and each scan syncs the graph. Try in Neo4j Browser:
```cypher
MATCH p=shortestPath((u:GitHubUser {name:'dev-user'})-[*..8]->(a:Resource)) WHERE a.criticality >= 7 RETURN p
```

## 5. Evaluation
- **Detection accuracy:** build 8-10 scenarios in your lab, write the expected (user, asset) pairs into `GROUND_TRUTH`, report precision, recall, runtime.
- **Cross-check:** export the same environment with BloodHound (AzureHound-style GitHub/AWS collectors) and compare paths; run Pacu only inside the sandbox account to confirm a path is exploitable.
- **Toxic combos:** report `toxic_share_pct` from `/api/toxic` (paths that need a combination vs. a single misconfiguration).
- **User study (20-30 participants, between-subjects):** group A reads BreachPath explanations, group B reads raw BloodHound graphs. Give 4 findings; measure time-to-answer, accuracy on 3 comprehension questions each, and a SUS usability score. Compare with a Mann-Whitney U test. Get consent, keep responses anonymous, and run a 3-person pilot first.

## 6. Deploy on EC2
Launch a t3.small (Ubuntu), install Docker, clone the repo, copy `.env`, run `docker compose up -d --build`. Attach an IAM instance role with the read-only permissions above instead of storing AWS keys. Restrict the security group to your IP or put it behind a VPN: the dashboard shows sensitive findings and has no login.

## 7. Known limits (write these in the paper)
- Workflow-to-role edges assume an attacker with repo write can edit workflows; branch protection and environment approvals are only approximated through the exploitability weight.
- IAM analysis covers identity policies. Permission boundaries, SCPs, resource policies and conditions are not evaluated.
- Secret scanning only finds AWS access key ids by regex in a capped set of files.
- Risk weights are expert-set; calibrate them against your scenarios.

## 8. Ideas to extend
PostgreSQL for scan history, a `/api/diff` between scans, Azure/GCP collectors, GitHub App auth, a Cypher-based second path engine for comparison.
