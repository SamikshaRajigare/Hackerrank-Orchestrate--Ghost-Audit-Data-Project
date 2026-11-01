from __future__ import annotations

import json
from typing import Any, Dict, List

PHASE_ORDER = {'FINDING': 0, 'REMEDIATION': 1, 'VERIFICATION': 2}
OPERATION_ORDER = {
    'REPORT_REMAINING_RECORD': 1,
    'REPORT_EXPOSED_PII': 2,
    'REPORT_ACTIVE_DATA_FLOW': 3,
    'REPORT_RESTORE_RISK': 4,
    'DISABLE_DATA_FLOW': 1,
    'BLOCK_RESTORE': 2,
    'DELETE_RECORD': 3,
    'REDACT_RECORD': 4,
    'ANONYMIZE_RECORD': 5,
    'VERIFY_RECORD_ABSENT': 1,
    'VERIFY_RECORD_PRESENT': 2,
    'VERIFY_RECORD_REDACTED': 3,
    'VERIFY_RECORD_ANONYMIZED': 4,
    'VERIFY_DATA_FLOW_DISABLED': 5,
    'VERIFY_RESTORE_BLOCKED': 6,
}


def sort_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(steps, key=lambda step: (
        PHASE_ORDER.get(str(step.get('phase', '')), 99),
        OPERATION_ORDER.get(str(step.get('operation', '')), 999),
        str(step.get('system_id', '')),
        str(step.get('resource_id', '')),
    ))


def finalize_steps(steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ordered = sort_steps(steps)
    normalized: List[Dict[str, Any]] = []
    for idx, step in enumerate(ordered, start=1):
        item = dict(step)
        item['step_no'] = idx
        normalized.append(item)
    return normalized


def jsonize_steps(steps: List[Dict[str, Any]]) -> str:
    return json.dumps(steps, separators=(',', ':'))
