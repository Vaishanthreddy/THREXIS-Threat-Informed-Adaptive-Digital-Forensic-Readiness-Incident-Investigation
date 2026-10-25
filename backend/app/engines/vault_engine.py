import os
import json
import uuid
import hashlib
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from backend.app.db.models import EvidenceVaultItem, SecurityEvent
from backend.app.core.config import settings

class EvidenceVaultEngine:
    def __init__(self, vault_dir: Optional[Path] = None):
        self.vault_dir = vault_dir or settings.VAULT_DIR
        self.vault_dir.mkdir(parents=True, exist_ok=True)

    def calculate_sha256_bytes(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def calculate_sha256_file(self, filepath: Path) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    async def acquire_evidence_from_events(
        self,
        db: AsyncSession,
        case_id: str,
        source_key: str,
        source_title: str,
        event_ids: List[str],
        original_source_path: str = "/var/log/auth.log"
    ) -> EvidenceVaultItem:
        """
        Acquires evidence from normalized security events, preserves raw records as an immutable file,
        calculates SHA-256, writes a tamper-evident manifest, and registers it in the vault.
        """
        # Fetch events
        events_query = select(SecurityEvent).where(SecurityEvent.event_id.in_(event_ids)).order_by(SecurityEvent.timestamp.asc())
        result = await db.execute(events_query)
        events = result.scalars().all()

        evidence_id = f"EVD-{datetime.datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        
        # Format acquired forensic package
        raw_lines = [e.raw_log for e in events]
        content_bytes = "\n".join(raw_lines).encode("utf-8")
        file_sha256 = self.calculate_sha256_bytes(content_bytes)

        # Storage paths
        case_vault_dir = self.vault_dir / case_id
        case_vault_dir.mkdir(parents=True, exist_ok=True)
        
        raw_evidence_filename = f"{evidence_id}_{source_key}.log"
        raw_evidence_path = case_vault_dir / raw_evidence_filename
        manifest_filename = f"{evidence_id}_{source_key}.manifest.json"
        manifest_path = case_vault_dir / manifest_filename

        # Write raw preserved evidence
        with open(raw_evidence_path, "wb") as f:
            f.write(content_bytes)

        # Create tamper-evident manifest
        manifest_data = {
            "evidence_id": evidence_id,
            "case_id": case_id,
            "source_key": source_key,
            "source_title": source_title,
            "original_source_path": original_source_path,
            "acquisition_timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "record_count": len(events),
            "file_size_bytes": len(content_bytes),
            "sha256_hash": file_sha256,
            "custody_chain": [
                {
                    "action": "ACQUISITION",
                    "actor": "THREXIS Adaptive Telemetry Collector",
                    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                    "verified_hash": file_sha256
                }
            ],
            "event_provenance": [
                {"event_id": e.event_id, "host": e.host, "timestamp": e.timestamp.isoformat(), "hash": e.sha256}
                for e in events
            ]
        }

        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

        # Store in database
        vault_item = EvidenceVaultItem(
            evidence_id=evidence_id,
            case_id=case_id,
            source_key=source_key,
            source_title=source_title,
            original_source_path=original_source_path,
            description=f"Preserved {len(events)} security events from {source_title} for case {case_id}",
            record_count=len(events),
            file_size_bytes=len(content_bytes),
            acquired_at=datetime.datetime.utcnow(),
            sha256_hash=file_sha256,
            integrity_status="VERIFIED",
            last_verified_at=datetime.datetime.utcnow(),
            storage_path=str(raw_evidence_path),
            manifest=manifest_data
        )
        db.add(vault_item)
        await db.commit()
        await db.refresh(vault_item)
        return vault_item

    async def verify_evidence_integrity(
        self,
        db: AsyncSession,
        evidence_id: str
    ) -> Dict[str, Any]:
        """
        Performs cryptographic verification of the physical file against the recorded SHA-256 hash.
        """
        result = await db.execute(select(EvidenceVaultItem).where(EvidenceVaultItem.evidence_id == evidence_id))
        item = result.scalars().first()
        if not item:
            return {"status": "ERROR", "message": f"Evidence {evidence_id} not found."}

        target_path = Path(item.storage_path)
        if not target_path.exists():
            item.integrity_status = "FILE_MISSING"
            await db.commit()
            return {
                "evidence_id": evidence_id,
                "status": "FILE_MISSING",
                "message": f"Evidence file at {target_path} is missing from vault storage.",
                "verified": False
            }

        current_hash = self.calculate_sha256_file(target_path)
        is_intact = (current_hash.lower() == item.sha256_hash.lower())
        
        now = datetime.datetime.utcnow()
        item.last_verified_at = now
        item.integrity_status = "VERIFIED" if is_intact else "TAMPERED"
        
        # Update manifest custody chain
        manifest = dict(item.manifest)
        custody = manifest.get("custody_chain", [])
        custody.append({
            "action": "INTEGRITY_VERIFICATION",
            "actor": "THREXIS Forensic Engine",
            "timestamp": now.isoformat() + "Z",
            "calculated_hash": current_hash,
            "expected_hash": item.sha256_hash,
            "status": "PASS" if is_intact else "FAIL"
        })
        manifest["custody_chain"] = custody
        item.manifest = manifest
        
        await db.commit()
        await db.refresh(item)

        return {
            "evidence_id": evidence_id,
            "expected_sha256": item.sha256_hash,
            "calculated_sha256": current_hash,
            "verified": is_intact,
            "status": "VERIFIED" if is_intact else "TAMPERED",
            "verified_at": now.isoformat() + "Z",
            "explanation": "Cryptographic SHA-256 match confirmed. File bit-level integrity verified." if is_intact else "CRITICAL: SHA-256 mismatch! File has been altered or corrupted."
        }

    async def get_all_vault_items(self, db: AsyncSession, case_id: Optional[str] = None) -> List[EvidenceVaultItem]:
        query = select(EvidenceVaultItem).order_by(EvidenceVaultItem.acquired_at.desc())
        if case_id:
            query = query.where(EvidenceVaultItem.case_id == case_id)
        result = await db.execute(query)
        return result.scalars().all()

vault_engine = EvidenceVaultEngine()
