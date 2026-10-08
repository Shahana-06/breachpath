"""Demo dataset (same shape the live collectors return) so the whole pipeline runs with no credentials.
Scenario designed to contain: a direct workflow takeover, a leaked-key pivot via Lambda, a wildcard OIDC trust
with an admin policy, and read-only users that must NOT get a path through a workflow."""
from ..schema import make_edge as E

ORG = "acme"


def _n(i, t, name, **p):
    return {"id": i, "type": t, "name": name, **p}


def get_mock():
    u = lambda x: f"gh:user:{x}"
    r = lambda x: f"gh:repo:{ORG}/{x}"
    w = lambda repo, f: f"gh:wf:{ORG}/{repo}:.github/workflows/{f}"
    arn = lambda kind, name: f"arn:aws:iam::123456789012:{kind}/{name}"

    gh_nodes = [_n(u(x), "GitHubUser", x) for x in ["dev-user", "intern-user", "alice", "carol", "viewer-bob"]]
    gh_nodes.append(_n("gh:team:devops-team", "GitHubTeam", "devops-team"))
    for repo in ["payment-service", "infra-config", "web-app", "infra-repo", "docs"]:
        gh_nodes.append(_n(r(repo), "Repository", repo, full_name=f"{ORG}/{repo}", default_branch="main"))
    wfs = [("payment-service", "deploy.yml", "DeployRole"), ("web-app", "build-and-deploy.yml", "WebAppRole"),
           ("infra-repo", "deploy-infra.yml", "InfraAdminRole")]
    for repo, f, role in wfs:
        gh_nodes.append(_n(w(repo, f), "Workflow", f, repo=f"{ORG}/{repo}", path=f".github/workflows/{f}",
                           declared_roles=[arn("role", role)]))
    gh_nodes.append(_n("secret:infra-config:aws.env", "Secret", "AWS key ...MPLE", access_key_id="AKIAIOSFODNN7EXAMPLE",
                       location="acme/infra-config/config/aws.env"))
    gh_edges = [
        E(u("dev-user"), r("payment-service"), "CAN_WRITE"),
        E(u("intern-user"), r("infra-config"), "CAN_READ"),
        E(u("intern-user"), r("payment-service"), "CAN_READ"),   # read-only: must not reach the workflow
        E(u("alice"), r("web-app"), "CAN_WRITE"),
        E(u("carol"), "gh:team:devops-team", "MEMBER_OF"),
        E("gh:team:devops-team", r("infra-repo"), "CAN_WRITE"),
        E(u("viewer-bob"), r("docs"), "CAN_READ"),
        E(r("infra-config"), "secret:infra-config:aws.env", "CONTAINS_SECRET"),
    ] + [E(r(repo), w(repo, f), "HAS_WORKFLOW") for repo, f, _ in wfs]

    res = lambda s, name, crit, **p: _n(f"aws:res:{s}:{name}", "Resource", name, service=s.upper(), criticality=crit,
                                       arn=f"arn:aws:{s}:::{name}", **p)
    aws_nodes = [
        _n("aws:role:DeployRole", "IAMRole", "DeployRole", arn=arn("role", "DeployRole"),
           oidc_subs=["repo:acme/payment-service:ref:refs/heads/main"]),
        _n("aws:role:WebAppRole", "IAMRole", "WebAppRole", arn=arn("role", "WebAppRole"), oidc_subs=["repo:acme/web-app:*"]),
        _n("aws:role:InfraAdminRole", "IAMRole", "InfraAdminRole", arn=arn("role", "InfraAdminRole"),
           oidc_subs=["repo:acme/infra-*"]),
        _n("aws:role:LambdaExecRole", "IAMRole", "LambdaExecRole", arn=arn("role", "LambdaExecRole")),
        _n("aws:user:lambda-deployer", "IAMUser", "lambda-deployer", arn=arn("user", "lambda-deployer"),
           access_key_ids=["AKIAIOSFODNN7EXAMPLE"]),
        _n("aws:policy:DeployPolicy", "IAMPolicy", "DeployPolicy", admin=False),
        _n("aws:policy:WebAppPolicy", "IAMPolicy", "WebAppPolicy", admin=False),
        _n("aws:policy:AdminPolicy", "IAMPolicy", "AdminPolicy", admin=True),
        _n("aws:policy:LambdaDeployPolicy", "IAMPolicy", "LambdaDeployPolicy", admin=False),
        _n("aws:policy:LambdaExecPolicy", "IAMPolicy", "LambdaExecPolicy", admin=False),
        res("rds", "prod-database", 10), res("s3", "customer-backups", 8), res("s3", "public-assets", 3),
        res("lambda", "order-processor", 5),
    ]
    P = lambda a, b, **p: E(f"aws:policy:{a}", f"aws:res:{b}", "CAN_ACCESS", **p)
    aws_edges = [
        E("aws:role:DeployRole", "aws:policy:DeployPolicy", "HAS_POLICY", admin=False),
        E("aws:role:WebAppRole", "aws:policy:WebAppPolicy", "HAS_POLICY", admin=False),
        E("aws:role:InfraAdminRole", "aws:policy:AdminPolicy", "HAS_POLICY", admin=True),
        E("aws:user:lambda-deployer", "aws:policy:LambdaDeployPolicy", "HAS_POLICY", admin=False),
        E("aws:role:LambdaExecRole", "aws:policy:LambdaExecPolicy", "HAS_POLICY", admin=False),
        E("aws:res:lambda:order-processor", "aws:role:LambdaExecRole", "EXECUTES_AS"),
        P("DeployPolicy", "rds:prod-database"),
        P("WebAppPolicy", "s3:public-assets"),
        P("AdminPolicy", "rds:prod-database"), P("AdminPolicy", "s3:customer-backups"),
        P("AdminPolicy", "s3:public-assets"), P("AdminPolicy", "lambda:order-processor", pivot=True),
        P("LambdaDeployPolicy", "lambda:order-processor", pivot=True),
        P("LambdaExecPolicy", "rds:prod-database"),
    ]
    return {"nodes": gh_nodes, "edges": gh_edges}, {"nodes": aws_nodes, "edges": aws_edges}
