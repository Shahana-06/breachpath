"""Collects users, teams, repos, workflows and exposed AWS keys from a GitHub org (read-only REST calls).
Run it only against organisations you own or are authorised to assess."""
import re
import requests
import yaml
from ..schema import make_edge

API = "https://api.github.com"
AWS_KEY_RE = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
SCAN_SUFFIXES = (".env", ".tf", ".tfvars", ".json", ".yml", ".yaml", ".py", ".js", ".sh", ".txt", ".cfg", ".ini", ".properties")


class GitHubCollector:
    def __init__(self, token: str, org: str, scan_secrets: bool = True, max_scan_files: int = 60):
        self.org, self.scan_secrets, self.max_scan = org, scan_secrets, max_scan_files
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                               "X-GitHub-Api-Version": "2022-11-28"})
        self.nodes, self.edges, self.warnings = {}, [], []

    # ---------- helpers
    def _get(self, url, params=None, raw=False):
        headers = {"Accept": "application/vnd.github.raw+json"} if raw else None
        r = self.s.get(url, params=params, headers=headers, timeout=30)
        if r.status_code in (403, 404, 409, 451):
            self.warnings.append(f"{r.status_code} for {url}")
            return None
        r.raise_for_status()
        return r.text if raw else r.json()

    def _paginate(self, url, params=None):
        params = dict(params or {}, per_page=100)
        page = 1
        while True:
            data = self._get(url, dict(params, page=page))
            if not data:
                return
            yield from data
            if len(data) < 100:
                return
            page += 1

    def _node(self, nid, ntype, name, **props):
        self.nodes[nid] = {"id": nid, "type": ntype, "name": name, **props}

    @staticmethod
    def _perm_rel(perms: dict):
        return "CAN_WRITE" if perms and (perms.get("push") or perms.get("maintain") or perms.get("admin")) else "CAN_READ"

    # ---------- main
    def collect(self) -> dict:
        repos = list(self._paginate(f"{API}/orgs/{self.org}/repos", {"type": "all"}))
        for repo in repos:
            full = repo["full_name"]
            rid = f"gh:repo:{full}"
            self._node(rid, "Repository", repo["name"], full_name=full, default_branch=repo.get("default_branch", "main"),
                       private=bool(repo.get("private")))
            for c in self._paginate(f"{API}/repos/{full}/collaborators", {"affiliation": "direct"}):
                uid = f"gh:user:{c['login']}"
                self._node(uid, "GitHubUser", c["login"])
                self.edges.append(make_edge(uid, rid, self._perm_rel(c.get("permissions"))))
            self._collect_workflows(repo, rid)
            if self.scan_secrets:
                self._scan_repo(repo, rid)
        self._collect_teams()
        return {"nodes": list(self.nodes.values()), "edges": self.edges, "warnings": self.warnings}

    def _collect_teams(self):
        for t in self._paginate(f"{API}/orgs/{self.org}/teams"):
            tid = f"gh:team:{t['slug']}"
            self._node(tid, "GitHubTeam", t["name"])
            for m in self._paginate(f"{API}/orgs/{self.org}/teams/{t['slug']}/members"):
                uid = f"gh:user:{m['login']}"
                self._node(uid, "GitHubUser", m["login"])
                self.edges.append(make_edge(uid, tid, "MEMBER_OF"))
            for r in self._paginate(f"{API}/orgs/{self.org}/teams/{t['slug']}/repos"):
                rid = f"gh:repo:{r['full_name']}"
                if rid in self.nodes:
                    self.edges.append(make_edge(tid, rid, self._perm_rel(r.get("permissions"))))

    def _collect_workflows(self, repo, rid):
        full = repo["full_name"]
        files = self._get(f"{API}/repos/{full}/contents/.github/workflows")
        for f in files or []:
            if not f["name"].endswith((".yml", ".yaml")):
                continue
            text = self._get(f"{API}/repos/{full}/contents/{f['path']}", raw=True) or ""
            roles = self._declared_roles(text)
            wid = f"gh:wf:{full}:{f['path']}"
            self._node(wid, "Workflow", f["name"], repo=full, path=f["path"], declared_roles=roles)
            self.edges.append(make_edge(rid, wid, "HAS_WORKFLOW"))

    @staticmethod
    def _declared_roles(text):
        roles = []
        try:
            doc = yaml.safe_load(text) or {}
            for job in (doc.get("jobs") or {}).values():
                for step in job.get("steps", []) or []:
                    arn = (step.get("with") or {}).get("role-to-assume")
                    if arn:
                        roles.append(str(arn))
        except Exception:
            pass
        return roles

    def _scan_repo(self, repo, rid):
        full, branch = repo["full_name"], repo.get("default_branch", "main")
        tree = self._get(f"{API}/repos/{full}/git/trees/{branch}", {"recursive": "1"})
        if not tree:
            return
        candidates = [t for t in tree.get("tree", []) if t["type"] == "blob" and t["path"].lower().endswith(SCAN_SUFFIXES)
                      and t.get("size", 0) < 100_000][: self.max_scan]
        for t in candidates:
            text = self._get(f"{API}/repos/{full}/contents/{t['path']}", raw=True) or ""
            for key in set(AWS_KEY_RE.findall(text)):
                sid = f"secret:{full}:{t['path']}:{key[-4:]}"
                self._node(sid, "Secret", f"AWS key ...{key[-4:]}", access_key_id=key, location=f"{full}/{t['path']}")
                self.edges.append(make_edge(rid, sid, "CONTAINS_SECRET"))
