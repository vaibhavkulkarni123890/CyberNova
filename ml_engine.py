# detection-service/ml_engine.py
import numpy as np
from sklearn.ensemble import IsolationForest, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from datetime import datetime
from typing import List, Dict, Any
import math

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

def _safe_dt(x):
    if isinstance(x, datetime):
        return x
    try:
        return datetime.fromisoformat(str(x).replace("Z",""))
    except Exception:
        return datetime.utcnow()

class ThreatModel:
    """
    Hybrid detector:
      1) Rule engine (signature & heuristics) -> rule_score [0..100]
      2) IsolationForest anomaly on features    -> anom_score [0..100]
      3) GBDT classifier risk                   -> clf_score  [0..100]
      Final risk = weighted blend + severity mapping
    """
    def __init__(self, contamination=0.02):  # Reduced from 0.05 to 0.02
        self.scaler = StandardScaler()
        self.anom = IsolationForest(contamination=contamination, random_state=42)
        self.clf = GradientBoostingClassifier(random_state=42)
        self._has_clf = False
        self.bootstrap()

    # --- Feature engineering ---
    def _encode_event_type(self, s: str) -> int:
        mapping = {
            "process_start": 1, "net_conn": 2, "file_write": 3, "login": 4,
            "http_req": 5, "dns_query": 6, "usb_insert": 7, "priv_escalation": 8
        }
        return mapping.get((s or "").lower(), 0)

    def _entropy(self, text: str) -> float:
        if not text:
            return 0.0
        from collections import Counter
        p, n = Counter(text), float(len(text))
        return -sum((c/n) * math.log2(c/n) for c in p.values())

    def _features_from_event(self, e: Dict[str, Any]) -> List[float]:
        et = self._encode_event_type(e.get("event_type"))
        ua = str(e.get("user_agent") or "")
        src = str(e.get("source_ip") or "")
        pl  = e.get("payload") or {}
        size = float(pl.get("bytes", pl.get("size", 0)) or 0)
        port = float(pl.get("dst_port", pl.get("port", 0)) or 0)
        proc = str(pl.get("process", ""))[:80]
        path = str(pl.get("path", ""))[:120]
        url  = str(pl.get("url", ""))[:120]
        ext  = (path.split(".")[-1] if "." in path else "").lower()
        ts   = _safe_dt(e.get("created_at")).hour

        return [
            et,
            len(src.split(".")),
            len(ua),
            self._entropy(proc + path + url),
            size,
            port,
            1.0 if ext in {"exe","dll","ps1","bat","js"} else 0.0,
            math.sin(2 * math.pi * ts / 24.0),
            math.cos(2 * math.pi * ts / 24.0),
        ]

    def _rule_score(self, e: Dict[str, Any]) -> float:
        """Simple but effective signatures/heuristics."""
        pl = e.get("payload") or {}
        msg = (str(pl.get("cmd", "")) + " " + str(pl.get("url","")) + " " + str(pl.get("path",""))).lower()
        score = 0
        bad_ext = any(x in msg for x in [".exe", ".dll", ".ps1", ".bat", ".js"])
        if bad_ext: score += 25
        if "powershell" in msg and ("-enc" in msg or "downloadstring" in msg): score += 35  # PS Encoded/LOLBins
        if "cmd /c" in msg or "certutil" in msg or "rundll32" in msg: score += 20
        if "http://" in msg or ("://raw." in msg): score += 10
        if "mimikatz" in msg or "lsass" in msg: score += 40
        if any(x in msg for x in ["union select", "or 1=1", "sleep(", "xp_cmdshell"]): score += 35  # SQLi
        if "sudo" in msg and "chmod 777" in msg: score += 15
        if "login_failed" in msg or "invalid password" in msg: score += 10
        return min(100, score)

    def bootstrap(self, n=400):
        """Create synthetic training so the pipeline works immediately."""
        rng = np.random.default_rng(1)
        fake_events = []
        for _ in range(n):
            e = {
                "event_type": rng.choice(["process_start","net_conn","file_write","login","http_req","dns_query"]),
                "source_ip": f"192.168.{rng.integers(0,5)}.{rng.integers(1,255)}",
                "user_agent": "Mozilla/5.0",
                "payload": {
                    "bytes": float(abs(rng.normal(20000, 12000))),
                    "dst_port": int(rng.choice([22,80,443,3389,8080,53])),
                    "process": rng.choice(["chrome.exe","svchost.exe","powershell.exe","python.exe","node.exe"]),
                    "path": rng.choice(["C:/Windows/System32/calc.exe", "C:/Users/Public/run.ps1", "/usr/bin/ssh"]),
                    "url": rng.choice(["https://example.com", "http://raw.example.net/payload", ""])
                },
                "created_at": datetime.utcnow()
            }
            fake_events.append(e)

        X = np.array([self._features_from_event(e) for e in fake_events])
        Xs = self.scaler.fit_transform(X)
        self.anom.fit(Xs)

        # crude labels for classifier
        y = np.array([1 if self._rule_score(e) > 35 else 0 for e in fake_events])
        if y.sum() > 10 and y.sum() < len(y):
            self.clf.fit(Xs, y)
            self._has_clf = True

    def score_event(self, e: Dict[str, Any]) -> Dict[str, Any]:
       x = np.array(self._features_from_event(e)).reshape(1, -1)
       xs = self.scaler.transform(x)

    # anomaly -> convert to [0..100] (lower score from IF means more anomalous)
       iso_raw = self.anom.decision_function(xs)[0]  # higher = less anomalous
       anom_score = float(np.interp(-iso_raw, [-0.5, 0.5], [0, 100]))

    # classifier probability
       if self._has_clf:
           p = float(self.clf.predict_proba(xs)[0, 1])
       else:
           p = 0.0
       clf_score = p * 100.0

       rule_score = self._rule_score(e)

    # Updated weights: more emphasis on classifier, less on anomaly
       final = 0.6 * clf_score + 0.3 * rule_score + 0.1 * anom_score

    # Updated severity thresholds with "safe" category
       if final < 35:
           severity = "safe"
       elif final < 50:
           severity = "low" 
       elif final < 70:
           severity = "medium"
       elif final < 85:
           severity = "high"
       else:
           severity = "critical"

       return {
           "rule_score": round(rule_score,2),
           "anom_score": round(anom_score,2),
           "clf_score": round(clf_score,2),
           "final_risk": round(final,2),
           "severity": severity
        }
   