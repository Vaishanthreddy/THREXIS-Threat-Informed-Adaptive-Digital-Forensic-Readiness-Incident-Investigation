import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, JSON, Boolean
from backend.app.db.session import Base

def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    host = Column(String(128), index=True, nullable=False)
    timestamp = Column(DateTime, index=True, nullable=False)
    source = Column(String(64), index=True, nullable=False)  # auth.log, journald, auditd, etc.
    event_type = Column(String(64), index=True, nullable=False)  # ssh_auth_failure, etc.
    user = Column(String(64), nullable=True, index=True)
    source_ip = Column(String(64), nullable=True, index=True)
    source_port = Column(Integer, nullable=True)
    pid = Column(Integer, nullable=True)
    message = Column(Text, nullable=False)
    raw_log = Column(Text, nullable=False)
    sha256 = Column(String(64), unique=True, index=True, nullable=False)
    ingested_at = Column(DateTime, default=utc_now, nullable=False)


class DetectionAlert(Base):
    __tablename__ = "detection_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, index=True, nullable=False)
    rule_id = Column(String(64), index=True, nullable=False)
    rule_name = Column(String(128), nullable=False)
    severity = Column(String(32), index=True, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    technique_id = Column(String(32), index=True, nullable=False)  # e.g., T1110
    technique_name = Column(String(128), nullable=False)
    tactic = Column(String(64), nullable=False)
    explanation = Column(Text, nullable=False)
    rationale = Column(Text, nullable=False)
    event_count = Column(Integer, default=1, nullable=False)
    first_event_at = Column(DateTime, nullable=False)
    last_event_at = Column(DateTime, nullable=False)
    source_host = Column(String(128), nullable=False)
    source_ip = Column(String(64), nullable=True)
    target_user = Column(String(64), nullable=True)
    supporting_event_ids = Column(JSON, default=list)
    status = Column(String(32), default="ACTIVE", index=True)  # ACTIVE, INVESTIGATING, CLOSED
    created_at = Column(DateTime, default=utc_now, nullable=False)


class EvidenceSourceStatus(Base):
    __tablename__ = "evidence_source_status"

    id = Column(Integer, primary_key=True, index=True)
    source_key = Column(String(64), unique=True, index=True, nullable=False)
    source_name = Column(String(128), nullable=False)
    category = Column(String(64), nullable=False)  # Authentication, System, Network, etc.
    threat_relevance_weight = Column(Float, default=1.0, nullable=False)  # w_i
    status = Column(String(32), default="unknown", nullable=False)  # unknown, missing, unavailable, available, collected, validated, not_applicable
    readiness_factor = Column(Float, default=0.0, nullable=False)  # s_i
    collection_cost = Column(Float, default=15.0, nullable=False)  # Cost in budget units
    last_activity_at = Column(DateTime, nullable=True)
    details = Column(Text, default="")
    remediation_action = Column(Text, default="")
    sample_count = Column(Integer, default=0)


class InvestigationCase(Base):
    __tablename__ = "investigation_cases"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String(64), unique=True, index=True, nullable=False)
    title = Column(String(256), nullable=False)
    status = Column(String(32), default="ACTIVE", index=True)  # ACTIVE, UNDER_REVIEW, PRESERVED, CLOSED
    severity = Column(String(32), default="HIGH", index=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)
    primary_technique = Column(String(64), nullable=False)
    summary = Column(Text, nullable=False)
    scope_and_methodology = Column(Text, default="")
    analyst_notes = Column(Text, default="")
    findings = Column(JSON, default=list)
    unresolved_questions = Column(JSON, default=list)
    readiness_score_at_time = Column(Float, default=0.0)
    supporting_event_ids = Column(JSON, default=list)
    supporting_alert_ids = Column(JSON, default=list)


class EvidenceVaultItem(Base):
    __tablename__ = "evidence_vault_items"

    id = Column(Integer, primary_key=True, index=True)
    evidence_id = Column(String(64), unique=True, index=True, nullable=False)
    case_id = Column(String(64), index=True, nullable=False)
    source_key = Column(String(64), nullable=False)
    source_title = Column(String(128), nullable=False)
    original_source_path = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    record_count = Column(Integer, default=0)
    file_size_bytes = Column(Integer, default=0)
    acquired_at = Column(DateTime, default=utc_now, nullable=False)
    sha256_hash = Column(String(64), index=True, nullable=False)
    integrity_status = Column(String(32), default="VERIFIED", index=True)  # VERIFIED, TAMPERED, UNVERIFIED
    last_verified_at = Column(DateTime, default=utc_now, nullable=False)
    storage_path = Column(String(256), nullable=False)
    manifest = Column(JSON, default=dict)


class PrioritizationRecord(Base):
    __tablename__ = "prioritization_records"

    id = Column(Integer, primary_key=True, index=True)
    run_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    strategy = Column(String(64), nullable=False)  # adaptive, static, random, threat_agnostic, frozen_context
    budget_limit = Column(Float, nullable=False)
    budget_used = Column(Float, nullable=False)
    selected_sources = Column(JSON, default=list)
    unselected_sources = Column(JSON, default=list)
    threat_context = Column(String(128), nullable=False)
    performance_metrics = Column(JSON, default=dict)


class CollectorHeartbeat(Base):
    __tablename__ = "collector_heartbeats"

    id = Column(Integer, primary_key=True, index=True)
    host_id = Column(String(64), unique=True, index=True, nullable=False)
    hostname = Column(String(128), nullable=False)
    ip_address = Column(String(64), nullable=False)
    collector_version = Column(String(32), nullable=False)
    os_info = Column(String(128), nullable=False)
    status = Column(String(32), default="ONLINE")  # ONLINE, DEGRADED, OFFLINE
    events_transmitted = Column(Integer, default=0)
    last_heartbeat_at = Column(DateTime, default=utc_now, nullable=False)


class ReadinessAssessmentHistory(Base):
    __tablename__ = "readiness_assessment_history"

    id = Column(Integer, primary_key=True, index=True)
    assessed_at = Column(DateTime, default=utc_now, nullable=False)
    score = Column(Float, nullable=False)
    weighted_sum = Column(Float, nullable=False)
    total_weights = Column(Float, nullable=False)
    coverage_percentage = Column(Float, nullable=False)
    gaps_count = Column(Integer, default=0)
    details = Column(JSON, default=dict)
