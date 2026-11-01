from __future__ import annotations

from typing import Any, Dict, List, Optional


class PolicyEngine:
    def __init__(self, rules: Any):
        self.rules = rules

    def required_action_for(self, system_id: str, resource_id: str, details: str = '') -> str:
        system_lower = (system_id or '').lower()
        resource_lower = (resource_id or '').lower()
        details_lower = (details or '').lower()
        if 'account' in resource_lower or system_lower == 'account_service':
            return 'DELETE'
        if system_lower == 'search_service' or 'search_' in resource_lower:
            return 'DELETE'
        if system_lower == 'export_service' or 'export_' in resource_lower:
            return 'DELETE'
        if system_lower == 'support_platform' or 'support_' in resource_lower:
            if 'conversation contains shared customer' in details_lower or 'shared customer' in details_lower or 'order context' in details_lower:
                return 'REDACT'
            return 'DELETE'
        if system_lower == 'analytics_platform' or 'analytics_' in resource_lower:
            return 'ANONYMIZE'
        if system_lower == 'integration_service' or 'data_flow_' in resource_lower:
            return 'DISABLE_DATA_FLOW'
        if system_lower == 'backup_service' or 'backup_' in resource_lower:
            return 'BLOCK_RESTORE'
        if system_lower == 'identity_service' or 'tombstone_' in resource_lower:
            return 'REDACT'
        if system_lower == 'security_service' or 'audit_record_' in resource_lower:
            return 'RETAIN'
        return 'DELETE'

    def action_to_step(self, phase: str, system_id: str, resource_id: str, action: str, evidence_id: str = '') -> Dict[str, str]:
        op_map = {
            'DELETE': ('DELETE_RECORD', 'ABSENT'),
            'REDACT': ('REDACT_RECORD', 'REDACTED'),
            'ANONYMIZE': ('ANONYMIZE_RECORD', 'ANONYMIZED'),
            'DISABLE_DATA_FLOW': ('DISABLE_DATA_FLOW', 'DISABLED'),
            'BLOCK_RESTORE': ('BLOCK_RESTORE', 'BLOCKED'),
            'RETAIN': ('VERIFY_RECORD_PRESENT', 'PRESENT'),
        }
        if phase == 'FINDING':
            if action == 'DELETE':
                return {'operation': 'REPORT_REMAINING_RECORD', 'state': 'PRESENT'}
            if action == 'REDACT':
                return {'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT'}
            if action == 'ANONYMIZE':
                return {'operation': 'REPORT_EXPOSED_PII', 'state': 'PRESENT'}
            if action == 'DISABLE_DATA_FLOW':
                return {'operation': 'REPORT_ACTIVE_DATA_FLOW', 'state': 'ACTIVE'}
            if action == 'BLOCK_RESTORE':
                return {'operation': 'REPORT_RESTORE_RISK', 'state': 'ACTIVE'}
        if phase == 'REMEDIATION':
            op, state = op_map.get(action, ('DELETE_RECORD', 'ABSENT'))
            return {'operation': op, 'state': state}
        if phase == 'VERIFICATION':
            if action == 'DELETE':
                return {'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT'}
            if action == 'REDACT':
                return {'operation': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED'}
            if action == 'ANONYMIZE':
                return {'operation': 'VERIFY_RECORD_ANONYMIZED', 'state': 'ANONYMIZED'}
            if action == 'DISABLE_DATA_FLOW':
                return {'operation': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED'}
            if action == 'BLOCK_RESTORE':
                return {'operation': 'VERIFY_RESTORE_BLOCKED', 'state': 'BLOCKED'}
            if action == 'RETAIN':
                return {'operation': 'VERIFY_RECORD_PRESENT', 'state': 'PRESENT'}
        return {'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT'}
