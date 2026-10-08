"""Graph schema: node types, relationship types and their default risk metadata."""
import math

NODE_TYPES = ["GitHubUser", "GitHubTeam", "Repository", "Workflow", "Secret",
              "OIDCProvider", "IAMUser", "IAMRole", "IAMPolicy", "Resource"]

# rel -> (exploitability 0-1, privilege level 1-5, permission sensitivity 0-1)
REL_DEFAULTS = {
    "CAN_READ":           (0.90, 1, 0.20),
    "CAN_WRITE":          (0.90, 2, 0.50),
    "MEMBER_OF":          (1.00, 1, 0.10),
    "HAS_WORKFLOW":       (0.90, 2, 0.60),
    "CONTAINS_SECRET":    (0.90, 3, 0.80),
    "GRANTS_CREDENTIALS": (0.85, 3, 0.90),
    "CAN_ASSUME":         (0.70, 4, 0.90),
    "HAS_POLICY":         (1.00, 4, 0.50),
    "CAN_ACCESS":         (0.90, 5, 1.00),
    "EXECUTES_AS":        (0.90, 4, 0.80),
    "TRUSTS":             (1.00, 1, 0.10),   # informational, never traversed
}
NON_TRAVERSABLE = {"TRUSTS"}


def make_edge(src, dst, rel, **props):
    expl, priv, sens = REL_DEFAULTS[rel]
    e = {"src": src, "dst": dst, "rel": rel, "exploitability": expl,
         "privilege": priv, "sensitivity": sens}
    e.update(props)
    e["traversable"] = rel not in NON_TRAVERSABLE
    return e


def edge_cost(e):
    """Lower cost = easier for an attacker. -ln(p) turns 'most probable path' into 'shortest path'."""
    return 0.1 + -math.log(max(e["exploitability"], 0.01))
