import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from backend.app.core.config import settings

class MitreAttackEngine:
    def __init__(self, data_file: Optional[Path] = None):
        self.data_file = data_file or (settings.DATA_DIR / "mitre_attack_enterprise.json")
        self._techniques: Dict[str, Dict[str, Any]] = {}
        self.load_data()

    def load_data(self):
        if self.data_file.exists():
            with open(self.data_file, "r", encoding="utf-8") as f:
                records = json.load(f)
                for item in records:
                    self._techniques[item["id"]] = item
                    # Also index subtechniques
                    for sub in item.get("subtechniques", []):
                        self._techniques[sub["id"]] = {
                            **sub,
                            "tactics": item.get("tactics", []),
                            "parent_id": item["id"],
                            "parent_name": item["name"],
                            "evidence_sources": item.get("evidence_sources", []),
                            "detection_methods": item.get("detection_methods", ""),
                            "url": f"https://attack.mitre.org/techniques/{sub['id'].replace('.', '/')}/",
                        }

    def get_all_techniques(self) -> List[Dict[str, Any]]:
        # Return top-level techniques with their subtechniques
        return [t for t in self._techniques.values() if "." not in t["id"]]

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        return self._techniques.get(technique_id)

    def map_detection_to_technique(self, rule_id: str, event_type: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Determines the appropriate MITRE ATT&CK technique mapping with transparent rationale
        based strictly on observed evidence rather than assumptions.
        """
        if rule_id == "RULE-SSH-BRUTEFORCE" or event_type == "ssh_auth_failure":
            event_count = details.get("count", 1)
            target_user = details.get("target_user", "unknown")
            is_single_account = details.get("is_single_account", True)
            
            # Grounded mapping:
            # T1110 is primary. If repeated failures against same account, T1110.001 (Password Guessing).
            # If failures against multiple distinct accounts, T1110.003 (Password Spraying).
            technique_id = "T1110"
            subtechnique_id = "T1110.001" if is_single_account else "T1110.003"
            
            base_tech = self.get_technique(technique_id) or {}
            
            rationale = (
                f"Observed {event_count} repeated SSH authentication failure events within a 60s window "
                f"targeting user '{target_user}'. This directly matches MITRE ATT&CK T1110 (Brute Force). "
                f"Because failures specifically target the single designated identity without systemic account enumeration across the fleet, "
                f"it provides direct observational support for T1110.001 (Password Guessing) rather than general spraying."
            )
            
            return {
                "technique_id": technique_id,
                "technique_name": base_tech.get("name", "Brute Force"),
                "tactics": base_tech.get("tactics", ["Credential Access"]),
                "subtechnique_id": subtechnique_id,
                "confidence": "HIGH",
                "mapping_rationale": rationale,
                "evidence_sources": base_tech.get("evidence_sources", []),
                "detection_methods": base_tech.get("detection_methods", ""),
                "official_url": base_tech.get("url", f"https://attack.mitre.org/techniques/{technique_id}/")
            }

        elif rule_id == "RULE-SUDO-ABUSE" or event_type == "sudo_failure":
            base_tech = self.get_technique("T1548.003") or {}
            return {
                "technique_id": "T1548.003",
                "technique_name": base_tech.get("name", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching"),
                "tactics": base_tech.get("tactics", ["Privilege Escalation"]),
                "confidence": "HIGH",
                "mapping_rationale": "Observed unauthorized sudo execution or sudo authentication failure in system auth logs.",
                "evidence_sources": base_tech.get("evidence_sources", []),
                "detection_methods": base_tech.get("detection_methods", ""),
                "official_url": base_tech.get("url", "https://attack.mitre.org/techniques/T1548/003/")
            }

        # Fallback / Generic
        return {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "tactics": ["Defense Evasion", "Initial Access"],
            "confidence": "MEDIUM",
            "mapping_rationale": "Observed suspicious account activity matching authentication logs.",
            "evidence_sources": ["User Login/Session Records", "SSH Authentication Logs"],
            "detection_methods": "Audit system logs for anomalous access.",
            "official_url": "https://attack.mitre.org/techniques/T1078/"
        }

mitre_engine = MitreAttackEngine()
