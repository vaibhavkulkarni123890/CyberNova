from sqlalchemy import Column, Integer, String, Float, DateTime, Text, Boolean, JSON, Index
from sqlalchemy.sql import func
from shared.database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    company = Column(String(150), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class WaitlistEntry(Base):
    __tablename__ = "waitlist"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# Raw telemetry from devices (ingested)
class TelemetryEvent(Base):
    __tablename__ = "telemetry_events"
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(100), index=True, nullable=False)
    user_id = Column(Integer, nullable=True)
    event_type = Column(String(100), nullable=False)   # process_start, net_conn, file_write, login, http_req, dns_query, ...
    payload = Column(JSON)                             # raw details
    source_ip = Column(String(45))
    user_agent = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
Index("ix_tel_device_time", TelemetryEvent.device_id, TelemetryEvent.created_at)


# Detection outputs (normalized)
class SecurityEvent(Base):
    __tablename__ = "security_events"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    device_id = Column(String(100), index=True)
    event_type = Column(String(100), nullable=False)   # Malware, Phishing Attempt, DDoS, SQL Injection, etc.
    severity = Column(String(50), nullable=False)      # low/medium/high/critical
    description = Column(Text)
    risk_score = Column(Float)
    source_ip = Column(String(45))
    is_blocked = Column(Boolean, default=False)
    event_metadata = Column(JSON)                      # model scores, rule hits, features
    detected_at = Column(DateTime(timezone=True), server_default=func.now())
Index("ix_sec_time", SecurityEvent.detected_at)


# Your analytics tables
class ThreatAnalytics(Base):
    __tablename__ = "threat_analytics"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    threat_type = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False)
    risk_score = Column(Float, nullable=False)
    source_ip = Column(String(45))
    target_system = Column(String(255))
    is_blocked = Column(Boolean, default=False)
    event_metadata = Column(Text)  # JSON string
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class UserBehavior(Base):
    __tablename__ = "user_behavior"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=False)
    action_type = Column(String(100), nullable=False)
    login_count = Column(Integer, default=0)
    failed_attempts = Column(Integer, default=0)
    session_duration = Column(Float, default=0)  # minutes
    ip_address = Column(String(45))
    user_agent = Column(Text)
    event_metadata = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SecurityMetrics(Base):
    __tablename__ = "security_metrics"
    id = Column(Integer, primary_key=True, index=True)
    metric_name = Column(String(100), nullable=False)
    metric_value = Column(Float, nullable=False)
    metric_type = Column(String(50), nullable=False)  # counter/gauge/histogram
    tags = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Prediction(Base):
    __tablename__ = "predictions"
    id = Column(Integer, primary_key=True, index=True)
    time = Column(DateTime(timezone=True), nullable=False, index=True)
    predicted_threat_count = Column(Integer, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())