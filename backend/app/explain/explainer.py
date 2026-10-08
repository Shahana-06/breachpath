"""Explainability layer: path -> plain English + simplified flow. Rule-based by default, optional LLM polish."""
import requests
from ..config import settings

FIXES = {
    "workflow_modify": "Protect the default branch, require pull-request reviews, and add CODEOWNERS for .github/workflows.",
    "wildcard_trust": "Pin the OIDC 'sub' condition to one repository and branch or environment instead of a wildcard.",
    "admin_policy": "Replace the administrator policy with a least-privilege policy for what the role really needs.",
    "secret_exposure": "Rotate the exposed AWS key, delete it from the repository, and use OIDC instead of long-lived keys.",
    "compute_pivot": "Limit lambda:UpdateFunctionCode to a deployment role and review what the function's role can reach.",
    "role_assumption": "Review which workflows are allowed to assume this role and require an approved environment.",
}


def describe_step(G, u, v):
    """Returns (sentence fragment, short flow label) for one edge."""
    e, V = G[u][v], G.nodes[v]
    n = V["name"]
    rel = e["rel"]
    if rel == "CAN_WRITE":
        return f"has write access to repository '{n}'", f"Push code to {n}"
    if rel == "CAN_READ":
        return f"can read repository '{n}'", f"Read {n}"
    if rel == "MEMBER_OF":
        return f"belongs to the '{n}' team", f"Member of {n}"
    if rel == "HAS_WORKFLOW":
        return f"can edit the '{n}' workflow, which runs in the pipeline", f"Edit {n}"
    if rel == "CONTAINS_SECRET":
        return f"can find an AWS access key stored at {V.get('location', n)}", "Find leaked AWS key"
    if rel == "GRANTS_CREDENTIALS":
        return f"can use that key to act as IAM user '{n}'", f"Act as {n}"
    if rel == "CAN_ASSUME":
        extra = " (the trust rule uses a wildcard)" if e.get("wildcard") else ""
        return f"is trusted to assume IAM role '{n}'{extra}", f"Assume role {n}"
    if rel == "HAS_POLICY":
        extra = " - an administrator policy" if e.get("admin") else ""
        return f"carries policy '{n}'{extra}", f"Policy {n}"
    if rel == "EXECUTES_AS":
        return f"runs as IAM role '{n}'", f"Runs as {n}"
    if rel == "CAN_ACCESS":
        if e.get("pivot"):
            return f"allows changing the code of {V.get('service', 'resource')} '{n}'", f"Change code of {n}"
        crit = " (critical asset)" if V.get("criticality", 0) >= settings.CRITICAL_THRESHOLD else ""
        return f"grants access to {V.get('service', 'resource')} '{n}'{crit}", f"Reach {n}"
    return f"is connected to '{n}'", n


def explain_path(G, path, rec) -> dict:
    steps, flow_edges = [], []
    for i, (u, v) in enumerate(zip(path, path[1:])):
        frag, label = describe_step(G, u, v)
        actor = f"'{G.nodes[path[0]]['name']}'" if i == 0 else "which"
        steps.append({"n": i + 1, "text": f"{actor} {frag}"})
        flow_edges.append({"source": u, "target": v, "label": label})
    target = G.nodes[path[-1]]
    summary = (f"If GitHub user '{G.nodes[path[0]]['name']}' is compromised, an attacker could reach "
               f"{target.get('service', 'resource')} '{target['name']}' in {rec['hops']} steps. "
               f"Risk {rec['score']}/100 ({rec['severity'].lower()}).")
    fixes = [FIXES[t] for t in ("secret_exposure", "workflow_modify", "wildcard_trust", "admin_policy", "compute_pivot",
                                "role_assumption") if t in rec["tags"]][:4]
    return {"summary": summary, "steps": steps, "fixes": fixes,
            "flow": {"nodes": rec["nodes"], "edges": flow_edges}}


def llm_explain(rec) -> str | None:
    """Optional: rewrite the structured finding for a non-expert. Only graph facts are sent (no secrets)."""
    if not settings.ANTHROPIC_API_KEY:
        return None
    facts = "\n".join(f"{s['n']}. {s['text']}" for s in rec["explanation"]["steps"])
    prompt = ("You explain cloud security findings to developers and managers. Using ONLY the facts below, write 3-4 "
              "plain-English sentences: what an attacker could do, why it matters, and the single best fix. "
              "Do not add facts.\n\nFacts:\n" + facts + f"\nRisk score: {rec['score']}/100\nSuggested fixes: "
              + " ".join(rec["explanation"]["fixes"]))
    try:
        r = requests.post("https://api.anthropic.com/v1/messages", timeout=30,
                          headers={"x-api-key": settings.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01",
                                   "content-type": "application/json"},
                          json={"model": settings.ANTHROPIC_MODEL, "max_tokens": 400,
                                "messages": [{"role": "user", "content": prompt}]})
        r.raise_for_status()
        return r.json()["content"][0]["text"]
    except Exception:
        return None
