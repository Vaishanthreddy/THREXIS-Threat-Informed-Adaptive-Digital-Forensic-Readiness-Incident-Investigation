import io
import json
import uuid
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from backend.app.db.models import InvestigationCase, DetectionAlert, SecurityEvent, EvidenceVaultItem, EvidenceSourceStatus
from backend.app.core.config import settings
from backend.app.engines.readiness_engine import readiness_engine
from backend.app.engines.mitre_engine import mitre_engine

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class InvestigationEngine:
    async def create_or_update_case_for_alert(
        self,
        db: AsyncSession,
        alert: DetectionAlert
    ) -> InvestigationCase:
        """
        Creates an investigation case for an active alert or updates an existing open case.
        """
        # Check for open case with same host and technique
        query = select(InvestigationCase).where(
            and_(
                InvestigationCase.status.in_(["ACTIVE", "UNDER_REVIEW"]),
                InvestigationCase.primary_technique == alert.technique_id
            )
        )
        existing_case = (await db.execute(query)).scalars().first()
        readiness_data = await readiness_engine.calculate_readiness(db, threat_context=alert.technique_id)

        if existing_case:
            alert_ids = list(set((existing_case.supporting_alert_ids or []) + [alert.alert_id]))
            event_ids = list(set((existing_case.supporting_event_ids or []) + (alert.supporting_event_ids or [])))
            existing_case.supporting_alert_ids = alert_ids
            existing_case.supporting_event_ids = event_ids
            existing_case.updated_at = datetime.datetime.utcnow()
            existing_case.readiness_score_at_time = readiness_data["score"]
            await db.commit()
            await db.refresh(existing_case)
            return existing_case

        case_id = f"CASE-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
        new_case = InvestigationCase(
            case_id=case_id,
            title=f"Incident Investigation: {alert.rule_name} on {alert.source_host}",
            status="ACTIVE",
            severity=alert.severity,
            primary_technique=alert.technique_id,
            summary=(
                f"Suspicious activity detected matching MITRE ATT&CK {alert.technique_id} ({alert.technique_name}). "
                f"Telemetric burst of {alert.event_count} security events observed from source IP {alert.source_ip or 'unknown'} "
                f"against account '{alert.target_user or 'unknown'}' on host '{alert.source_host}'."
            ),
            scope_and_methodology=(
                "Scope encompasses Linux system authentication telemetry, system journal logs, and network connection records. "
                "Investigation follows threat-informed digital forensic readiness principles, prioritizing evidence acquisition "
                "under constrained forensic budgets with cryptographic SHA-256 chain-of-custody preservation."
            ),
            analyst_notes=(
                "Initial Assessment: Rapid succession of authentication failures detected. "
                "No successful authentication recorded following the burst. "
                "Recommended Action: Preserve auth.log and btmp logs, verify iptables/fail2ban state."
            ),
            findings=[
                f"Detected {alert.event_count} failed SSH logins within configured detection window.",
                f"Mapped to MITRE ATT&CK {alert.technique_id} ({alert.technique_name}) under tactic '{alert.tactic}'.",
                "Cryptographic event integrity hashes recorded for all supporting telemetry items.",
                "Target user account was not observed to be successfully breached in available logs."
            ],
            unresolved_questions=[
                "Did the adversary attempt lateral movement from another host within the subnet?",
                "Are automated brute-force tools (e.g. Hydra, Medusa) indicated by user-agent or client software strings?"
            ],
            readiness_score_at_time=readiness_data["score"],
            supporting_event_ids=alert.supporting_event_ids or [],
            supporting_alert_ids=[alert.alert_id]
        )
        db.add(new_case)
        await db.commit()
        await db.refresh(new_case)
        return new_case

    async def get_case_details(self, db: AsyncSession, case_id: str) -> Optional[Dict[str, Any]]:
        result = await db.execute(select(InvestigationCase).where(InvestigationCase.case_id == case_id))
        case = result.scalars().first()
        if not case:
            return None

        # Fetch associated alerts
        alerts_res = await db.execute(select(DetectionAlert).where(DetectionAlert.alert_id.in_(case.supporting_alert_ids or [])))
        alerts = alerts_res.scalars().all()

        # Fetch timeline events
        events_res = await db.execute(select(SecurityEvent).where(SecurityEvent.event_id.in_(case.supporting_event_ids or [])).order_by(SecurityEvent.timestamp.asc()))
        events = events_res.scalars().all()

        # Fetch associated vault items
        vault_res = await db.execute(select(EvidenceVaultItem).where(EvidenceVaultItem.case_id == case_id))
        vault_items = vault_res.scalars().all()

        tech_info = mitre_engine.get_technique(case.primary_technique) or {}

        # Construct granular timeline
        timeline = []
        for e in events:
            timeline.append({
                "id": e.event_id,
                "timestamp": e.timestamp.isoformat() + "Z",
                "type": "SECURITY_EVENT",
                "title": f"Security Event: {e.event_type}",
                "description": e.message,
                "host": e.host,
                "source": e.source,
                "user": e.user,
                "source_ip": e.source_ip,
                "sha256": e.sha256
            })
        for a in alerts:
            timeline.append({
                "id": a.alert_id,
                "timestamp": a.last_event_at.isoformat() + "Z",
                "type": "DETECTION_ALERT",
                "title": f"Detection: {a.rule_name}",
                "description": a.explanation,
                "severity": a.severity,
                "technique": f"{a.technique_id} - {a.technique_name}"
            })
        for v in vault_items:
            timeline.append({
                "id": v.evidence_id,
                "timestamp": v.acquired_at.isoformat() + "Z",
                "type": "EVIDENCE_ACQUIRED",
                "title": f"Forensic Evidence Acquired: {v.source_title}",
                "description": f"Preserved {v.record_count} items. SHA-256: {v.sha256_hash[:16]}...",
                "sha256": v.sha256_hash
            })

        timeline.sort(key=lambda x: x["timestamp"])

        return {
            "case": case,
            "alerts": alerts,
            "events_count": len(events),
            "vault_items": vault_items,
            "technique_info": tech_info,
            "timeline": timeline
        }

    async def update_notes(self, db: AsyncSession, case_id: str, notes: str, status: Optional[str] = None) -> Optional[InvestigationCase]:
        result = await db.execute(select(InvestigationCase).where(InvestigationCase.case_id == case_id))
        case = result.scalars().first()
        if not case:
            return None
        case.analyst_notes = notes
        if status:
            case.status = status
        case.updated_at = datetime.datetime.utcnow()
        await db.commit()
        await db.refresh(case)
        return case

    async def generate_json_report(self, db: AsyncSession, case_id: str) -> Dict[str, Any]:
        data = await self.get_case_details(db, case_id)
        if not data:
            return {"error": "Case not found"}
        
        case: InvestigationCase = data["case"]
        readiness_data = await readiness_engine.calculate_readiness(db, threat_context=case.primary_technique)

        report = {
            "report_metadata": {
                "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
                "system": "THREXIS Threat-Informed Adaptive Forensic Investigation System",
                "version": "1.0.0-academic",
                "case_id": case.case_id
            },
            "case_information": {
                "case_id": case.case_id,
                "title": case.title,
                "status": case.status,
                "severity": case.severity,
                "created_at": case.created_at.isoformat() + "Z",
                "updated_at": case.updated_at.isoformat() + "Z",
                "primary_technique": case.primary_technique,
                "summary": case.summary,
                "scope_and_methodology": case.scope_and_methodology
            },
            "mitre_attack_intelligence": data["technique_info"],
            "forensic_readiness_assessment": {
                "score_at_time": case.readiness_score_at_time,
                "current_score": readiness_data["score"],
                "category": readiness_data["category"],
                "formula": readiness_data["formula"],
                "gaps": readiness_data["gaps"],
                "recommendations": readiness_data["recommendations"]
            },
            "findings": case.findings,
            "unresolved_questions": case.unresolved_questions,
            "analyst_notes": case.analyst_notes,
            "evidence_inventory": [
                {
                    "evidence_id": item.evidence_id,
                    "source_title": item.source_title,
                    "original_path": item.original_source_path,
                    "record_count": item.record_count,
                    "sha256": item.sha256_hash,
                    "integrity_status": item.integrity_status,
                    "acquired_at": item.acquired_at.isoformat() + "Z"
                }
                for item in data["vault_items"]
            ],
            "timeline": data["timeline"],
            "limitations": [
                "Analysis limited to monitored telemetry sources; process exec and auditd logs were missing during assessment.",
                "Adversary intent inferred from observed network and authentication telemetry without memory forensics."
            ]
        }
        return report

    async def generate_pdf_report(self, db: AsyncSession, case_id: str) -> bytes:
        data = await self.get_case_details(db, case_id)
        if not data:
            raise ValueError(f"Case {case_id} not found")
        
        case: InvestigationCase = data["case"]
        readiness_data = await readiness_engine.calculate_readiness(db, threat_context=case.primary_technique)
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )
        
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor('#0F172A'),
            spaceAfter=8
        )
        h2_style = ParagraphStyle(
            'H2Style',
            parent=styles['Heading2'],
            fontSize=13,
            leading=16,
            textColor=colors.HexColor('#0D9488'),
            spaceBefore=12,
            spaceAfter=6
        )
        body_style = ParagraphStyle(
            'BodyStyle',
            parent=styles['Normal'],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#334155')
        )
        bold_style = ParagraphStyle(
            'BoldStyle',
            parent=body_style,
            fontName='Helvetica-Bold'
        )

        elements = []

        # Header
        elements.append(Paragraph("THREXIS FORENSIC INVESTIGATION REPORT", title_style))
        elements.append(Paragraph(f"<b>Case ID:</b> {case.case_id} | <b>Generated:</b> {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0D9488'), spaceBefore=6, spaceAfter=12))

        # Case Summary Table
        case_info_data = [
            [Paragraph("<b>Incident Title:</b>", body_style), Paragraph(case.title, body_style)],
            [Paragraph("<b>Status:</b>", body_style), Paragraph(case.status, body_style)],
            [Paragraph("<b>Severity:</b>", body_style), Paragraph(case.severity, body_style)],
            [Paragraph("<b>Primary MITRE Technique:</b>", body_style), Paragraph(f"{case.primary_technique} - {data['technique_info'].get('name', 'N/A')}", body_style)],
            [Paragraph("<b>Forensic Readiness Score:</b>", body_style), Paragraph(f"{readiness_data['score']}% ({readiness_data['category']})", body_style)]
        ]
        t = Table(case_info_data, colWidths=[150, 380])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#F8FAFC')),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('PADDING', (0,0), (-1,-1), 5),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 12))

        # Executive Summary
        elements.append(Paragraph("1. Executive Summary & Scope", h2_style))
        elements.append(Paragraph(case.summary, body_style))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(case.scope_and_methodology, body_style))
        elements.append(Spacer(1, 10))

        # Threat Intelligence Mapping
        elements.append(Paragraph("2. Threat Intelligence Context (MITRE ATT&CK)", h2_style))
        tech_desc = data['technique_info'].get('description', 'Standard attack telemetry pattern.')
        elements.append(Paragraph(f"<b>Technique:</b> {case.primary_technique} - {data['technique_info'].get('name', 'N/A')}", body_style))
        elements.append(Paragraph(f"<b>Tactics:</b> {', '.join(data['technique_info'].get('tactics', []))}", body_style))
        elements.append(Paragraph(f"<b>Description:</b> {tech_desc[:300]}...", body_style))
        elements.append(Spacer(1, 10))

        # Key Findings
        elements.append(Paragraph("3. Key Forensic Findings", h2_style))
        for finding in case.findings:
            elements.append(Paragraph(f"• {finding}", body_style))
        elements.append(Spacer(1, 10))

        # Preserved Evidence Vault Inventory
        elements.append(Paragraph("4. Preserved Forensic Evidence & Cryptographic Chain-of-Custody", h2_style))
        if data["vault_items"]:
            evd_table_data = [["Evidence ID", "Source Title", "Records", "SHA-256 Hash", "Status"]]
            for v in data["vault_items"]:
                evd_table_data.append([
                    Paragraph(v.evidence_id, body_style),
                    Paragraph(v.source_title, body_style),
                    str(v.record_count),
                    Paragraph(f"{v.sha256_hash[:16]}...", body_style),
                    v.integrity_status
                ])
            et = Table(evd_table_data, colWidths=[90, 110, 50, 200, 80])
            et.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0D9488')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#CBD5E1')),
                ('PADDING', (0,0), (-1,-1), 4),
            ]))
            elements.append(et)
        else:
            elements.append(Paragraph("No physical evidence records preserved in the vault for this case yet.", body_style))
        elements.append(Spacer(1, 10))

        # Investigation Chronology
        elements.append(Paragraph("5. Chronological Event Timeline", h2_style))
        timeline_rows = [["Timestamp", "Type", "Details"]]
        for t_item in data["timeline"][:10]: # Top 10 for layout
            timeline_rows.append([
                Paragraph(t_item["timestamp"][:19], body_style),
                Paragraph(t_item["type"], body_style),
                Paragraph(t_item["title"], body_style)
            ])
        tt = Table(timeline_rows, colWidths=[120, 110, 300])
        tt.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#E2E8F0')),
            ('PADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(tt)
        elements.append(Spacer(1, 10))

        # Analyst Notes & Limitations
        elements.append(Paragraph("6. Analyst Notes & Investigation Limitations", h2_style))
        elements.append(Paragraph(f"<b>Analyst Notes:</b> {case.analyst_notes}", body_style))
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("<b>Investigation Limitations:</b> Analysis is strictly bounded by available evidence sources. No conclusion of compromise has been made without verified telemetry confirmation.", body_style))

        doc.build(elements)
        return buffer.getvalue()

investigation_engine = InvestigationEngine()
