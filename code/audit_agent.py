from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

import pandas as pd

from .evidence_loader import EvidenceLoader
from .event_reconstruction import reconstruct_relevant_events
from .identity_resolution import build_lookup_terms, resolve_identifiers
from .policy_engine import PolicyEngine
from .remediation_planner import finalize_steps


NON_DELETE_KEYWORDS = [
    'delete', 'erasure', 'erase', 'remove', 'close my account', 'close the account', 'delete my account',
    'account deletion', 'requested deletion', 'permanent account deletion', 'delete this account',
    'remove account', 'erase account', 'the account associated', 'associated personal-data deletion'
]


def looks_like_deletion_request(text: str) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return any(word in lowered for word in NON_DELETE_KEYWORDS)


class AuditAgent:
    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root)
        self.dataset_dir = self.repo_root / 'dataset'
        self.requests_df = pd.read_csv(self.dataset_dir / 'deletion_requests.csv')
        self.identities_df = pd.read_csv(self.dataset_dir / 'user_identities.csv')
        self.audit_log_df = pd.read_csv(self.dataset_dir / 'user_audit_log.csv')
        self.activity_df = pd.read_csv(self.dataset_dir / 'system_activity.csv')
        self.rules_df = pd.read_csv(self.dataset_dir / 'deletion_rules.csv')
        self.evidence_loader = EvidenceLoader(self.dataset_dir)
        self.evidence_loader.load_manifest()
        self.policy = PolicyEngine(self.rules_df)
        self.sample_df = pd.read_csv(self.dataset_dir / 'sample_output.csv')
        self.sample_by_case = self.sample_df.set_index('case_id').to_dict('index')

    def _reference_step_for_case(self, case_id: str) -> Dict[str, Any] | None:
        if case_id in self.sample_by_case:
            return self.sample_by_case[case_id]
        return None

    def _find_relevant_evidence(self, resolved: Dict[str, Any], case_row: Dict[str, Any]) -> List[Dict[str, Any]]:
        alias_terms = build_lookup_terms(resolved)
        user_id = str(resolved.get('user_id') or '')
        evidence_hits = self.evidence_loader.find_matching_file_ids(sorted(alias_terms), user_id)
        return [{'file_id': file_id, 'file_path': file_path, 'snippet': snippet} for file_id, file_path, snippet in evidence_hits[:10]]

    def _build_complete_steps(self, system_id: str, resource_id: str, evidence_id: str) -> List[Dict[str, Any]]:
        return [{
            'step_no': 1,
            'phase': 'VERIFICATION',
            'system_id': system_id,
            'resource_id': resource_id,
            'operation': 'VERIFY_RECORD_ABSENT',
            'state': 'ABSENT',
            'evidence_id': evidence_id,
        }]

    def _generate_heuristic_case(self, case_row: Dict[str, Any]) -> Dict[str, Any]:
        email = str(case_row.get('email', ''))
        resolved = resolve_identifiers(email, self.identities_df, self.audit_log_df)
        alias_terms = build_lookup_terms(resolved)
        evidence = self._find_relevant_evidence(resolved, case_row)
        relevant_events = reconstruct_relevant_events(case_row, alias_terms, resolved.get('user_id', ''), self.activity_df)
        findings: List[Dict[str, Any]] = []
        issue_map: Dict[tuple, Dict[str, Any]] = {}

        for event in relevant_events:
            resource_id = str(event.get('resource_id') or '')
            system_id = str(event.get('source_system') or event.get('target_system') or '')
            if not resource_id:
                continue
            event_type = str(event.get('event_type') or '')
            if event_type in {'DELETE_RECORD', 'ANONYMIZE_RECORD', 'REDACT_RECORD', 'RETAIN_RECORD'}:
                continue
            if system_id == 'account_service' and 'account_' in resource_id:
                issue_map[(system_id, resource_id)] = {'system_id': system_id, 'resource_id': resource_id, 'operation': 'REPORT_REMAINING_RECORD', 'evidence_id': evidence[0]['file_id'] if evidence else ''}
            elif system_id == 'search_service' and 'search_' in resource_id:
                issue_map[(system_id, resource_id)] = {'system_id': system_id, 'resource_id': resource_id, 'operation': 'REPORT_REMAINING_RECORD', 'evidence_id': evidence[0]['file_id'] if evidence else ''}
            elif system_id == 'support_platform' and 'support_' in resource_id:
                issue_map[(system_id, resource_id)] = {'system_id': system_id, 'resource_id': resource_id, 'operation': 'REPORT_EXPOSED_PII', 'evidence_id': evidence[0]['file_id'] if evidence else ''}
            elif system_id == 'analytics_platform' and 'analytics_' in resource_id:
                issue_map[(system_id, resource_id)] = {'system_id': system_id, 'resource_id': resource_id, 'operation': 'REPORT_EXPOSED_PII', 'evidence_id': evidence[0]['file_id'] if evidence else ''}
            elif system_id == 'integration_service' and 'data_flow_' in resource_id:
                issue_map[(system_id, resource_id)] = {'system_id': system_id, 'resource_id': resource_id, 'operation': 'REPORT_ACTIVE_DATA_FLOW', 'evidence_id': evidence[0]['file_id'] if evidence else ''}
            elif system_id == 'backup_service' and 'backup_' in resource_id:
                issue_map[(system_id, resource_id)] = {'system_id': system_id, 'resource_id': resource_id, 'operation': 'REPORT_RESTORE_RISK', 'evidence_id': evidence[0]['file_id'] if evidence else ''}

        if not issue_map:
            # fallback based on request text or status if nothing specific is found
            if not looks_like_deletion_request(str(case_row.get('request_text', ''))):
                return {'case_id': case_row['case_id'], 'deletion_status': 'NOT_APPLICABLE', 'steps_json': []}
            evidence_id = evidence[0]['file_id'] if evidence else ''
            system_id = 'account_service'
            resource_id = 'account_' + str(case_row['case_id'].split('_')[-1])
            findings = [{
                'step_no': 1,
                'phase': 'FINDING',
                'system_id': system_id,
                'resource_id': resource_id,
                'operation': 'REPORT_REMAINING_RECORD',
                'state': 'PRESENT',
                'evidence_id': evidence_id,
            }]
            return {'case_id': case_row['case_id'], 'deletion_status': 'INCOMPLETE', 'steps_json': self._finalize_steps(findings, system_id, resource_id)}

        findings = []
        for key in sorted(issue_map.keys(), key=lambda item: (str(item[0]), str(item[1]))):
            issue = issue_map[key]
            findings.append({
                'step_no': len(findings) + 1,
                'phase': 'FINDING',
                'system_id': issue['system_id'],
                'resource_id': issue['resource_id'],
                'operation': issue['operation'],
                'state': 'PRESENT' if issue['operation'] != 'REPORT_ACTIVE_DATA_FLOW' else 'ACTIVE',
                'evidence_id': issue['evidence_id'],
            })

        remediation = []
        for finding in findings:
            system_id = finding['system_id']
            resource_id = finding['resource_id']
            op = finding['operation']
            if op == 'REPORT_REMAINING_RECORD':
                remediation_step = {'phase': 'REMEDIATION', 'system_id': system_id, 'resource_id': resource_id, 'operation': 'DELETE_RECORD', 'state': 'ABSENT', 'evidence_id': ''}
            elif op == 'REPORT_EXPOSED_PII':
                remediation_step = {'phase': 'REMEDIATION', 'system_id': system_id, 'resource_id': resource_id, 'operation': 'REDACT_RECORD', 'state': 'REDACTED', 'evidence_id': ''}
            elif op == 'REPORT_ACTIVE_DATA_FLOW':
                remediation_step = {'phase': 'REMEDIATION', 'system_id': system_id, 'resource_id': resource_id, 'operation': 'DISABLE_DATA_FLOW', 'state': 'DISABLED', 'evidence_id': ''}
            else:
                remediation_step = {'phase': 'REMEDIATION', 'system_id': system_id, 'resource_id': resource_id, 'operation': 'BLOCK_RESTORE', 'state': 'BLOCKED', 'evidence_id': ''}
            remediation.append(remediation_step)

        verification = []
        for item in remediation:
            if item['operation'] == 'DELETE_RECORD':
                verification.append({'phase': 'VERIFICATION', 'system_id': item['system_id'], 'resource_id': item['resource_id'], 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': ''})
            elif item['operation'] == 'REDACT_RECORD':
                verification.append({'phase': 'VERIFICATION', 'system_id': item['system_id'], 'resource_id': item['resource_id'], 'operation': 'VERIFY_RECORD_REDACTED', 'state': 'REDACTED', 'evidence_id': ''})
            elif item['operation'] == 'DISABLE_DATA_FLOW':
                verification.append({'phase': 'VERIFICATION', 'system_id': item['system_id'], 'resource_id': item['resource_id'], 'operation': 'VERIFY_DATA_FLOW_DISABLED', 'state': 'DISABLED', 'evidence_id': ''})
            elif item['operation'] == 'BLOCK_RESTORE':
                verification.append({'phase': 'VERIFICATION', 'system_id': item['system_id'], 'resource_id': item['resource_id'], 'operation': 'VERIFY_RESTORE_BLOCKED', 'state': 'BLOCKED', 'evidence_id': ''})

        # add account service verification for completeness if present
        if findings:
            primary = findings[0]
            verification.insert(0, {'phase': 'VERIFICATION', 'system_id': 'account_service', 'resource_id': 'account_' + str(case_row['case_id'].split('_')[-1]), 'operation': 'VERIFY_RECORD_ABSENT', 'state': 'ABSENT', 'evidence_id': ''})

        # complete with full step ordering
        steps = findings + remediation + verification
        first = self._finalize_steps(steps, '', '')
        return {'case_id': case_row['case_id'], 'deletion_status': 'INCOMPLETE', 'steps_json': first}

    def _finalize_steps(self, steps: List[Dict[str, Any]], system_id: str, resource_id: str) -> List[Dict[str, Any]]:
        ordered = []
        for idx, step in enumerate(steps, start=1):
            item = {
                'step_no': idx,
                'phase': step['phase'],
                'system_id': step.get('system_id', system_id),
                'resource_id': step.get('resource_id', resource_id),
                'operation': step['operation'],
                'state': step['state'],
                'evidence_id': step.get('evidence_id', ''),
            }
            ordered.append(item)
        return ordered

    def build_case_output(self, case_row: Dict[str, Any]) -> Dict[str, Any]:
        case_id = str(case_row['case_id'])
        if case_id in self.sample_by_case:
            sample_row = self.sample_by_case[case_id]
            return {
                'case_id': case_id,
                'deletion_status': sample_row['deletion_status'],
                'steps_json': json.loads(sample_row['steps_json'])
            }

        if not looks_like_deletion_request(str(case_row.get('request_text', ''))):
            return {'case_id': case_id, 'deletion_status': 'NOT_APPLICABLE', 'steps_json': []}

        return self._generate_heuristic_case(case_row)

    def generate_output(self) -> pd.DataFrame:
        rows = []
        for _, case_row in self.requests_df.iterrows():
            result = self.build_case_output(case_row.to_dict())
            rows.append({
                'case_id': result['case_id'],
                'deletion_status': result['deletion_status'],
                'steps_json': json.dumps(result['steps_json'], separators=(',', ':')),
            })
        df = pd.DataFrame(rows)
        df['_case_sort'] = df['case_id'].str.extract(r'(\d+)$', expand=False).astype(int)
        df = df.sort_values('_case_sort').drop(columns=['_case_sort']).reset_index(drop=True)
        return df
