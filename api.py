"""REST API for the audit platform (FastAPI).

Exposes the audit engine headless so it can be embedded in pipelines, consumed
by other tools, or used as a CI/CD gate. Run with:

    uvicorn api:app --host 0.0.0.0 --port 8000
"""

from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from audit_platform import inventory, scheduler, storage
from audit_platform.osint.cyber_analysis import CyberAnalysisAdapter
from audit_platform.scoring import PostureScore, score_findings

app = FastAPI(
    title="MHcheck Audit Platform API",
    description="Continuous security posture auditing for your services.",
    version="1.0.0",
)


class AuditRequest(BaseModel):
    target: str
    persist: bool = True


class AuditResponse(BaseModel):
    target: str
    posture: PostureScore
    findings: list
    report: dict


class GateResponse(BaseModel):
    target: str
    grade: str
    score: int
    min_grade: str
    passed: bool


class AssetRequest(BaseModel):
    name: str
    target: str
    asset_type: str = "domain"
    group: str = "default"
    tags: List[str] = []
    environment: str = "production"
    owner: str = ""
    tenant: str = "default"


GRADES = ["A", "B", "C", "D", "F"]


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/audit", response_model=AuditResponse)
def run_audit(req: AuditRequest):
    adapter = CyberAnalysisAdapter()
    report = adapter.analyze_target(req.target)
    posture = score_findings(report.findings)
    if req.persist:
        storage.save_scan(
            target=report.target,
            source=report.metadata.source,
            score=posture.score,
            grade=posture.grade,
            findings=[f.model_dump() for f in report.findings],
            report=report.model_dump(mode="json"),
            run_id=report.metadata.run_id,
        )
    return AuditResponse(
        target=report.target,
        posture=posture,
        findings=[f.model_dump() for f in report.findings],
        report=report.model_dump(mode="json"),
    )


@app.get("/gate", response_model=GateResponse)
def gate(target: str, min_grade: str = "B"):
    threshold = min_grade.upper()
    if threshold not in GRADES:
        raise HTTPException(status_code=400, detail=f"min_grade must be one of {GRADES}")
    adapter = CyberAnalysisAdapter()
    report = adapter.analyze_target(target)
    posture = score_findings(report.findings)
    passed = GRADES.index(posture.grade) <= GRADES.index(threshold)
    return GateResponse(
        target=target, grade=posture.grade, score=posture.score, min_grade=threshold, passed=passed
    )


@app.get("/history")
def history(target: Optional[str] = None):
    if target:
        return {"target": target, "scans": storage.get_recent_scans(target, limit=10)}
    return {"targets": storage.list_targets()}


@app.get("/diff")
def diff(target: str):
    result = storage.diff_scans(target)
    if result is None:
        raise HTTPException(status_code=404, detail="Not enough history to compute a diff")
    return result


@app.get("/assets")
def get_assets(tenant: Optional[str] = None):
    return {"assets": inventory.list_assets(tenant=tenant)}


@app.post("/assets")
def create_asset(req: AssetRequest):
    asset_id = inventory.add_asset(
        name=req.name, target=req.target, asset_type=req.asset_type, group=req.group,
        tags=req.tags, environment=req.environment, owner=req.owner, tenant=req.tenant,
    )
    return {"id": asset_id}


@app.delete("/assets/{asset_id}")
def remove_asset(asset_id: int):
    if not inventory.delete_asset(asset_id):
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"deleted": asset_id}


@app.post("/fleet/audit")
def fleet_audit(tenant: Optional[str] = None):
    return {"results": scheduler.run_fleet_audit(tenant=tenant)}
