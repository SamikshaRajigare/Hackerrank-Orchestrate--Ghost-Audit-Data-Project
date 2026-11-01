from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Set


def normalize_email(value: Any) -> str:
    return str(value).strip().lower() if value is not None and str(value).strip() else ""


def normalize_identifier(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    return re.sub(r"\s+", "", text)


def resolve_identifiers(email: str, identities: Any, audit_log: Any) -> Dict[str, Any]:
    norm_email = normalize_email(email)
    if not norm_email:
        return {"user_id": "", "current_email": "", "historical_emails": [], "aliases": []}

    identities = identities.copy()
    match = identities[identities['email'].str.lower() == norm_email]
    if match.empty:
        # try historical aliases in audit log by email value
        hist = []
        for _, row in audit_log.iterrows():
            if normalize_identifier(row.get('old_value')) == normalize_identifier(norm_email):
                hist.append(row['new_value'])
            if normalize_identifier(row.get('new_value')) == normalize_identifier(norm_email):
                hist.append(row['old_value'])
        return {"user_id": "", "current_email": norm_email, "historical_emails": hist, "aliases": [norm_email] + hist}

    user_row = match.sort_values('updated_at').iloc[-1]
    user_id = str(user_row['user_id'])
    current_email = normalize_email(user_row.get('email'))
    historical = []
    for _, row in audit_log.iterrows():
        if str(row.get('user_id')) == user_id:
            if row.get('field_name') in {'email', 'previous_email'}:
                val = row.get('old_value')
                if val:
                    historical.append(normalize_email(val))
                val2 = row.get('new_value')
                if val2:
                    historical.append(normalize_email(val2))
    aliases = [v for v in list(dict.fromkeys([current_email] + historical + [norm_email])) if v]
    return {
        "user_id": user_id,
        "current_email": current_email,
        "historical_emails": historical,
        "aliases": aliases,
        "identity_values": [current_email] + historical + [norm_email],
    }


def build_lookup_terms(resolved: Dict[str, Any]) -> Set[str]:
    terms: Set[str] = set()
    for key in ['current_email', 'user_id']:
        value = resolved.get(key)
        if value:
            terms.add(str(value).strip())
    for alias in resolved.get('aliases', []):
        if alias:
            terms.add(str(alias).strip())
    for alias in resolved.get('identity_values', []):
        if alias:
            terms.add(str(alias).strip())
    return {term.lower() for term in terms if term}
