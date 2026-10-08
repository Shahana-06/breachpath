"""Collects IAM roles/users/policies and key resources (S3, RDS, Lambda) with read-only boto3 calls.
Needs: iam:List*/Get*, s3:ListAllMyBuckets, rds:DescribeDBInstances, lambda:ListFunctions."""
import fnmatch
import boto3
from ..config import settings
from ..schema import make_edge

GITHUB_OIDC_HOST = "token.actions.githubusercontent.com"


def _as_list(x):
    return x if isinstance(x, list) else [x]


def criticality_for(name: str, tags: dict | None = None) -> int:
    if tags and tags.get("breachpath:criticality", "").isdigit():
        return int(tags["breachpath:criticality"])
    return 9 if any(k in name.lower() for k in settings.CRITICAL_KEYWORDS) else 3


class AWSCollector:
    def __init__(self, profile: str = "", region: str = ""):
        self.session = boto3.Session(profile_name=profile or None, region_name=region or None)
        self.iam = self.session.client("iam")
        self.nodes, self.edges = {}, []

    def collect(self) -> dict:
        self._resources()
        self._policy_cache = {}
        self._users()
        self._roles()
        return {"nodes": list(self.nodes.values()), "edges": self.edges}

    # ---------- resources
    def _resources(self):
        for b in self.session.client("s3").list_buckets().get("Buckets", []):
            self._add_res(f"arn:aws:s3:::{b['Name']}", "s3", b["Name"])
        for db in self.session.client("rds").describe_db_instances().get("DBInstances", []):
            self._add_res(db["DBInstanceArn"], "rds", db["DBInstanceIdentifier"])
        lam = self.session.client("lambda")
        for fn in lam.list_functions().get("Functions", []):
            nid = self._add_res(fn["FunctionArn"], "lambda", fn["FunctionName"])
            self.nodes[nid]["exec_role_arn"] = fn["Role"]

    def _add_res(self, arn, service, name):
        nid = f"aws:res:{service}:{name}"
        self.nodes[nid] = {"id": nid, "type": "Resource", "name": name, "service": service.upper(),
                           "arn": arn, "criticality": criticality_for(name)}
        return nid

    # ---------- identities
    def _users(self):
        for page in self.iam.get_paginator("list_users").paginate():
            for u in page["Users"]:
                nid = f"aws:user:{u['UserName']}"
                keys = [k["AccessKeyId"] for k in self.iam.list_access_keys(UserName=u["UserName"])["AccessKeyMetadata"]]
                self.nodes[nid] = {"id": nid, "type": "IAMUser", "name": u["UserName"], "arn": u["Arn"], "access_key_ids": keys}
                attached = self.iam.list_attached_user_policies(UserName=u["UserName"])["AttachedPolicies"]
                for p in attached:
                    self._attach(nid, p["PolicyArn"], p["PolicyName"])
                for pn in self.iam.list_user_policies(UserName=u["UserName"])["PolicyNames"]:
                    doc = self.iam.get_user_policy(UserName=u["UserName"], PolicyName=pn)["PolicyDocument"]
                    self._attach_inline(nid, f"{u['UserName']}/{pn}", doc)

    def _roles(self):
        for page in self.iam.get_paginator("list_roles").paginate():
            for r in page["Roles"]:
                if r["Path"].startswith("/aws-service-role/"):
                    continue
                nid = f"aws:role:{r['RoleName']}"
                subs, missing, principals = self._parse_trust(r["AssumeRolePolicyDocument"])
                self.nodes[nid] = {"id": nid, "type": "IAMRole", "name": r["RoleName"], "arn": r["Arn"],
                                   "oidc_subs": subs, "oidc_missing_sub": missing, "trusted_principals": principals}
                for p in self.iam.list_attached_role_policies(RoleName=r["RoleName"])["AttachedPolicies"]:
                    self._attach(nid, p["PolicyArn"], p["PolicyName"])
                for pn in self.iam.list_role_policies(RoleName=r["RoleName"])["PolicyNames"]:
                    doc = self.iam.get_role_policy(RoleName=r["RoleName"], PolicyName=pn)["PolicyDocument"]
                    self._attach_inline(nid, f"{r['RoleName']}/{pn}", doc)
        # lambda -> execution role
        for n in list(self.nodes.values()):
            if n.get("exec_role_arn"):
                role = next((x for x in self.nodes.values() if x.get("arn") == n["exec_role_arn"]), None)
                if role:
                    self.edges.append(make_edge(n["id"], role["id"], "EXECUTES_AS"))

    @staticmethod
    def _parse_trust(doc):
        subs, principals, oidc_seen, sub_seen = [], [], False, False
        for st in _as_list(doc.get("Statement", [])):
            if st.get("Effect") != "Allow":
                continue
            princ = st.get("Principal", {})
            fed = _as_list(princ.get("Federated", [])) if isinstance(princ, dict) else []
            if any(GITHUB_OIDC_HOST in f for f in fed):
                oidc_seen = True
                for cond in st.get("Condition", {}).values():
                    for k, v in cond.items():
                        if k.endswith(":sub"):
                            sub_seen = True
                            subs += _as_list(v)
            if isinstance(princ, dict):
                principals += [p for p in _as_list(princ.get("AWS", [])) if p.startswith("arn:")]
        return subs, (oidc_seen and not sub_seen), principals

    # ---------- policies
    def _attach(self, owner, arn, name):
        if arn not in self._policy_cache:
            meta = self.iam.get_policy(PolicyArn=arn)["Policy"]
            self._policy_cache[arn] = self.iam.get_policy_version(PolicyArn=arn, VersionId=meta["DefaultVersionId"])["PolicyVersion"]["Document"]
        self._make_policy(owner, f"aws:policy:{name}", name, self._policy_cache[arn])

    def _attach_inline(self, owner, name, doc):
        self._make_policy(owner, f"aws:policy:inline:{name}", name, doc)

    def _make_policy(self, owner, pid, name, doc):
        statements = [s for s in _as_list(doc.get("Statement", [])) if s.get("Effect") == "Allow"]
        admin = any("*" in _as_list(s.get("Action", [])) and "*" in _as_list(s.get("Resource", [])) for s in statements)
        self.nodes[pid] = {"id": pid, "type": "IAMPolicy", "name": name, "admin": admin}
        self.edges.append(make_edge(owner, pid, "HAS_POLICY", admin=admin))
        for res in [n for n in self.nodes.values() if n["type"] == "Resource"]:
            hit = self._grants(statements, res)
            if hit:
                self.edges.append(make_edge(pid, res["id"], "CAN_ACCESS", pivot=(hit == "pivot")))

    @staticmethod
    def _grants(statements, res):
        svc = res["service"].lower()
        for st in statements:
            resources = _as_list(st.get("Resource", []))
            if not any(fnmatch.fnmatchcase(res["arn"], rp) for rp in resources):
                continue
            actions = _as_list(st.get("Action", []))
            if svc == "lambda":
                if any(fnmatch.fnmatchcase("lambda:UpdateFunctionCode", a) or fnmatch.fnmatchcase("lambda:UpdateFunctionConfiguration", a) for a in actions):
                    return "pivot"
            elif any(a == "*" or a.lower().startswith(f"{svc}:") for a in actions):
                return "access"
        return None
