from __future__ import annotations

from typing import Any, Dict, List, Set


def event_matches_identity(row: Dict[str, Any], identities: Set[str], user_id: str) -> bool:
    text = ' '.join([
        str(row.get('details', '') or ''),
        str(row.get('resource_id', '') or ''),
        str(row.get('source_system', '') or ''),
        str(row.get('target_system', '') or ''),
    ]).lower()
    if user_id and user_id.lower() in text:
        return True
    for value in identities:
        if value and value.lower() in text:
            return True
    return False


def reconstruct_relevant_events(case_row: Dict[str, Any], identities: Set[str], user_id: str, activity_df: Any) -> List[Dict[str, Any]]:
    relevant: List[Dict[str, Any]] = []
    audit_at = case_row.get('audit_at')
    for _, row in activity_df.iterrows():
        if audit_at and row.get('event_time') and row['event_time'] > audit_at:
            continue
        if event_matches_identity(row.to_dict(), identities, user_id):
            relevant.append(row.to_dict())
    return relevant
