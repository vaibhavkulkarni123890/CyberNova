from fastapi import FastAPI, Depends, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func
from shared.database import init_db, get_db
from shared.models import TelemetryEvent, SecurityEvent, Prediction  # Added Prediction model import
from ml_engine import ThreatModel
from datetime import datetime
import asyncio, json, os

app = FastAPI(title="CyberGuard Detection Service", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

init_db()
model = ThreatModel()
QUEUE_MAX = 5000
process_queue: "asyncio.Queue[Dict[str,Any]]" = asyncio.Queue(maxsize=QUEUE_MAX)

# Simple in-memory WS hub
class WSManager:
    def __init__(self):
        self.active: List[WebSocket] = []
    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)
    async def broadcast(self, message: Dict[str, Any]):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(json.dumps(message))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)
ws_manager = WSManager()

# --------------------- Analytics API endpoints ---------------------

@app.get("/api/analytics/dashboard-metrics")
def dashboard_metrics(db: Session = Depends(get_db)) -> Dict[str, Any]:
    # Aggregate threat counts by severity level from real DB data
    data = db.query(SecurityEvent.severity, func.count(SecurityEvent.id))\
             .group_by(SecurityEvent.severity).all()
    return {"metrics": {severity: count for severity, count in data}}

@app.get("/api/analytics/risk-assessment")
def risk_assessment(db: Session = Depends(get_db)) -> Dict[str, Any]:
    # Compute average and maximum risk score from real DB
    avg_risk = db.query(func.avg(SecurityEvent.risk_score)).scalar() or 0
    max_risk = db.query(func.max(SecurityEvent.risk_score)).scalar() or 0
    return {"averageRiskScore": avg_risk, "maxRiskScore": max_risk}

@app.get("/api/analytics/predictions")
def predictions(db: Session = Depends(get_db)) -> Dict[str, Any]:
    # Fetch prediction records from DB ordered by time
    records = db.query(Prediction).order_by(Prediction.time.asc()).all()
    return {
        "predictions": [
            {
                "time": rec.time.isoformat(),
                "predicted_threat_count": rec.predicted_threat_count
            }
            for rec in records
        ]
    }

# --------------------- Detection Service core ---------------------

@app.on_event("startup")
async def start_worker():
    async def worker():
        while True:
            item = await process_queue.get()
            await _process_event(item)
            process_queue.task_done()
    asyncio.create_task(worker())

async def _process_event(ev: Dict[str,Any]):
    # 1) persist raw telemetry
    db: Session
    for db in get_db():
        t = TelemetryEvent(
            device_id=ev.get("device_id"),
            user_id=ev.get("user_id"),
            event_type=ev.get("event_type"),
            payload=ev.get("payload"),
            source_ip=ev.get("source_ip"),
            user_agent=ev.get("user_agent"),
        )
        db.add(t)
        db.commit()
        db.refresh(t)

        # 2) score
        scores = model.score_event({
            "event_type": t.event_type,
            "source_ip": t.source_ip,
            "user_agent": t.user_agent,
            "payload": t.payload,
            "created_at": t.created_at
        })

        sev = scores["severity"]
        evt = SecurityEvent(
            user_id=t.user_id,
            device_id=t.device_id,
            event_type=_normalize_type(t, scores),
            severity=sev,
            description=_describe(t, scores),
            risk_score=scores["final_risk"],
            source_ip=t.source_ip,
            is_blocked=_should_block(scores),
            event_metadata=scores,
        )
        db.add(evt)
        db.commit()
        db.refresh(evt)

        # 3) notify subscribers (UI/API-gateway can subscribe)
        await ws_manager.broadcast({
            "type": "threat_detected",
            "id": evt.id,
            "severity": evt.severity,
            "risk": evt.risk_score,
            "event_type": evt.event_type,
            "device_id": evt.device_id,
            "detectedAt": evt.detected_at.isoformat()
        })

def _normalize_type(t: TelemetryEvent, scores: Dict[str,Any]) -> str:
    et = t.event_type
    msg = json.dumps(t.payload or {}).lower()
    if "union select" in msg or "xp_cmdshell" in msg: return "SQL Injection"
    if "powershell" in msg or ".ps1" in msg: return "Malware Detection"
    if '"dst_port":3389' in msg or '"dst_port":22' in msg: return "Brute Force Attack"
    if et == "http_req" and ("phish" in msg or "signin" in msg and "oauth" in msg): return "Phishing Attempt"
    if et == "net_conn" and (t.payload or {}).get("bytes", 0) > 5e7: return "DDoS Attack"
    return "Suspicious Activity"

def _describe(t: TelemetryEvent, scores: Dict[str,Any]) -> str:
    return f"{t.event_type} from {t.source_ip or 'unknown'}; risk={scores['final_risk']}"

def _should_block(scores: Dict[str,Any]) -> bool:
    return scores["final_risk"] >= 85 or (scores["severity"] in {"high","critical"} and scores["anom_score"] > 70)

# ---- Public API ----

@app.post("/api/ingest")
async def ingest(event: Dict[str,Any], background: BackgroundTasks):
    """Called by user devices/agents to send telemetry."""
    # Required minimal fields:
    for key in ("device_id","event_type"):
        if key not in event:
            return {"status": "error", "message": f"missing {key}"}
    if process_queue.full():
        return {"status":"backpressure","message":"queue is full, try later"}
    await process_queue.put({
        "device_id": event["device_id"],
        "user_id": event.get("user_id"),
        "event_type": event["event_type"],
        "payload": event.get("payload", {}),
        "source_ip": event.get("source_ip"),
        "user_agent": event.get("user_agent"),
        "created_at": datetime.utcnow().isoformat()
    })
    return {"status":"queued"}

@app.get("/api/threats/recent")
def recent(limit: int = 50, db: Session = Depends(get_db)):
    rows = db.query(SecurityEvent).order_by(SecurityEvent.detected_at.desc()).limit(limit).all()
    return [{
        "id": r.id,
        "eventType": r.event_type,
        "severity": r.severity,
        "description": r.description,
        "riskScore": r.risk_score,
        "sourceIp": r.source_ip,
        "isBlocked": r.is_blocked,
        "detectedAt": r.detected_at.isoformat()
    } for r in rows]

@app.get("/api/threats/stats")
def stats(db: Session = Depends(get_db)):
    total = db.query(func.count(SecurityEvent.id)).scalar() or 0
    blocked = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.is_blocked.is_(True)).scalar() or 0
    critical = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.severity=="critical").scalar() or 0
    avg = db.query(func.avg(SecurityEvent.risk_score)).scalar() or 0
    return {"totalThreats": total, "blockedThreats": blocked, "criticalThreats": critical, "averageRiskScore": float(avg or 0)}

@app.websocket("/ws/stream")
async def ws_stream(ws: WebSocket):
    await ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()  # keepalive/ignore client messages
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)

@app.get("/health")
def health():
    return {"status":"ok","model":"hybrid-ensemble","queue": process_queue.qsize()}
