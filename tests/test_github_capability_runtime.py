from __future__ import annotations
import os, sys, unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
from fastapi.testclient import TestClient
ROOT=Path(__file__).resolve().parents[1]; SRC=ROOT/"src"
if str(SRC) not in sys.path: sys.path.insert(0,str(SRC))
from jas_si_agent import api as api_module
from jas_si_agent.github_capability_identity import WorkloadIdentity
from jas_si_agent.github_capability_runtime import create_github_capability_app, require_enabled_authenticated_workload
class Capability:
    task_id=uuid4(); tenant_id=uuid4(); installation_id=12345; repository_full_name="owner/private-repo"
    capability_role="worker"; commit_sha="a"*40; repository_paths=["src/main.py"]
    from datetime import datetime, timezone
    expires_at=datetime(2030,1,1,tzinfo=timezone.utc)
class Broker:
    def __init__(self): self.kwargs=None
    def resolve(self,**kwargs): self.kwargs=kwargs; return Capability()
class Proxy:
    def read_file(self,**kwargs): return {"repository":kwargs["repository"],"commit_sha":kwargs["commit_sha"],"path":kwargs["path"],"blob_sha":"b"*40,"content_base64":"eA==","content_bytes":1}
    def read_commit(self,**kwargs): return {"repository":kwargs["repository"],"commit_sha":kwargs["commit_sha"],"tree_sha":"c"*40}
    def close(self): pass
def settings(enabled=True,environment="preview"):
    return SimpleNamespace(github_capability_broker_enabled=enabled,environment=environment,
        github_capability_broker_database_url="postgresql://x:y@db.example.test/db?sslmode=verify-full",
        github_capability_workload_identities=None)
class BrokerRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.identity=WorkloadIdentity("worker.staging.instance-1","worker"); self.broker=Broker()
        self.app=create_github_capability_app(settings(),broker_factory=lambda dsn:self.broker,read_proxy_factory=lambda _:Proxy())
        self.app.dependency_overrides[require_enabled_authenticated_workload]=lambda:self.identity
    def test_public_api_does_not_mount_broker_routes(self):
        paths={getattr(r,"path",None) for r in api_module.app.routes}
        self.assertNotIn("/internal/github/capabilities/read",paths)
    def test_isolated_routes_only(self):
        paths={getattr(r,"path",None) for r in self.app.routes}
        self.assertEqual(paths,{"/internal/github/capabilities/resolve","/internal/github/capabilities/read","/internal/github/capabilities/commit"})
        self.assertIsNone(self.app.openapi_url)
    def test_resolve_uses_current_workload_identity_contract(self):
        task=uuid4()
        with TestClient(self.app) as client: response=client.post("/internal/github/capabilities/resolve",json={"task_id":str(task),"lease_fence":7})
        self.assertEqual(response.status_code,200); self.assertEqual(self.broker.kwargs,{"task_id":task,"identity":self.identity,"lease_fence":7,"verifier_claim_token":None})
        self.assertNotIn("tenant_id",response.json()); self.assertNotIn("installation_id",response.json())
    def test_file_and_commit_routes_re_resolve_task_capability(self):
        body={"task_id":str(uuid4()),"lease_fence":7,"repository":"owner/private-repo","commit_sha":"a"*40}
        with TestClient(self.app) as client:
            a=client.post("/internal/github/capabilities/read",json={**body,"path":"src/main.py"})
            b=client.post("/internal/github/capabilities/commit",json=body)
        self.assertEqual(a.status_code,200); self.assertEqual(b.status_code,200); self.assertEqual(b.json()["tree_sha"],"c"*40)
    def test_role_proof_and_client_identity_fields_fail_closed(self):
        with TestClient(self.app) as client:
            missing=client.post("/internal/github/capabilities/read",json={"task_id":str(uuid4()),"repository":"owner/private-repo","commit_sha":"a"*40,"path":"src/main.py"})
            forged=client.post("/internal/github/capabilities/resolve",json={"task_id":str(uuid4()),"lease_fence":1,"principal_id":"attacker","role":"worker"})
        self.assertEqual(missing.status_code,422); self.assertEqual(forged.status_code,422)
    def test_tls_listener_defaults_to_isolated_broker_app(self):
        from jas_si_agent.github_capability_tls_server import load_application
        with patch.dict(os.environ, {}, clear=True):
            application = load_application()
        self.assertEqual(application.title, "JAS-SI GitHub Capability Broker")

    def test_tls_listener_rejects_public_api_override(self):
        from jas_si_agent.github_capability_tls_server import load_application
        with patch.dict(os.environ, {"JAS_SI_CAPABILITY_TLS_ASGI_APP": "jas_si_agent.api:app"}, clear=False):
            with self.assertRaisesRegex(RuntimeError, "isolated Broker"):
                load_application()

    def test_disabled_and_production_modes_are_not_found(self):
        for config in (settings(False),settings(True,"production")):
            app=create_github_capability_app(config)
            with TestClient(app) as client: response=client.post("/internal/github/capabilities/resolve",json={"task_id":str(uuid4()),"lease_fence":1})
            self.assertEqual(response.status_code,404)
if __name__=="__main__": unittest.main()
