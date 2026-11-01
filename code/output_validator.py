from __future__ import annotations

import json
from typing import Any, Dict, List

import pandas as pd

ALLOWED_OPERATIONS = {
    'REPORT_REMAINING_RECORD', 'REPORT_EXPOSED_PII', 'REPORT_ACTIVE_DATA_FLOW', 'REPORT_RESTORE_RISK',
    'DISABLE_DATA_FLOW', 'BLOCK_RESTORE', 'DELETE_RECORD', 'REDACT_RECORD', 'ANONYMIZE_RECORD',
    'VERIFY_RECORD_ABSENT', 'VERIFY_RECORD_PRESENT', 'VERIFY_RECORD_REDACTED', 'VERIFY_RECORD_ANONYMIZED',
    'VERIFY_DATA_FLOW_DISABLED', 'VERIFY_RESTORE_BLOCKED'
}
ALLOWED_PHASES = {'FINDING', 'REMEDIATION', 'VERIFICATION'}
STATE_MAP = {
    'REPORT_REMAINING_RECORD': 'PRESENT', 'REPORT_EXPOSED_PII': 'PRESENT', 'REPORT_ACTIVE_DATA_FLOW': 'ACTIVE',
    'REPORT_RESTORE_RISK': 'ACTIVE', 'DISABLE_DATA_FLOW': 'DISABLED', 'BLOCK_RESTORE': 'BLOCKED',
    'DELETE_RECORD': 'ABSENT', 'REDACT_RECORD': 'REDACTED', 'ANONYMIZE_RECORD': 'ANONYMIZED',
    'VERIFY_RECORD_ABSENT': 'ABSENT', 'VERIFY_RECORD_PRESENT': 'PRESENT', 'VERIFY_RECORD_REDACTED': 'REDACTED',
    'VERIFY_RECORD_ANONYMIZED': 'ANONYMIZED', 'VERIFY_DATA_FLOW_DISABLED': 'DISABLED', 'VERIFY_RESTORE_BLOCKED': 'BLOCKED'
}


def validate_output_df(output_df: pd.DataFrame, requests_df: pd.DataFrame, sample_output_df: pd.DataFrame | None = None) -> None:
    expected_cols = ['case_id', 'deletion_status', 'steps_json']
    if list(output_df.columns) != expected_cols:
        raise ValueError(f'Unexpected CSV columns: {list(output_df.columns)}')
    if len(output_df) != len(requests_df):
        raise ValueError(f'Expected {len(requests_df)} rows, got {len(output_df)}')
    if sorted(output_df['case_id'].tolist()) != sorted(requests_df['case_id'].tolist()):
        raise ValueError('Case IDs do not match requests file')
    output_df = output_df.sort_values('case_id').reset_index(drop=True)
    for _, row in output_df.iterrows():
        status = str(row['deletion_status'])
        if status not in {'COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'}:
            raise ValueError(f'Invalid deletion status: {status}')
        steps = json.loads(row['steps_json'])
        if not isinstance(steps, list):
            raise ValueError(f'JSON steps must be array for case {row.case_id}')
        if status == 'NOT_APPLICABLE':
            if steps != []:
                raise ValueError(f'NOT_APPLICABLE case {row.case_id} requires []')
            continue
        if not steps:
            raise ValueError(f'Empty steps for non-NOT_APPLICABLE case {row.case_id}')
        step_nos = [int(step['step_no']) for step in steps]
        if step_nos != list(range(1, len(steps) + 1)):
            raise ValueError(f'Invalid step numbers for case {row.case_id}: {step_nos}')
        for step in steps:
            if step['phase'] not in ALLOWED_PHASES:
                raise ValueError(f'Invalid phase for {row.case_id}: {step}')
            if step['operation'] not in ALLOWED_OPERATIONS:
                raise ValueError(f'Invalid operation for {row.case_id}: {step}')
            if step['state'] != STATE_MAP.get(step['operation']):
                raise ValueError(f'Invalid state for {row.case_id}: {step}')
            if 'evidence_id' not in step:
                raise ValueError(f'Missing evidence_id for {row.case_id}: {step}')
            if step['phase'] in {'FINDING', 'VERIFICATION'} and status == 'COMPLETE':
                if not step['evidence_id']:
                    raise ValueError(f'COMPLETE case requires evidence_id for {row.case_id}: {step}')
            if step['phase'] == 'REMEDIATION':
                if step['evidence_id']:
                    raise ValueError(f'Remediation steps must have empty evidence_id for {row.case_id}: {step}')
    if sample_output_df is not None:
        sample_map = sample_output_df.set_index('case_id').to_dict('index')
        for case_id, sample_row in sample_map.items():
            if case_id in set(output_df['case_id']):
                generated = output_df[output_df['case_id'] == case_id].iloc[0].to_dict()
                if generated['deletion_status'] != sample_row['deletion_status']:
                    raise ValueError(f'Sample mismatch status for {case_id}: expected {sample_row["deletion_status"]}, got {generated["deletion_status"]}')
                if json.loads(generated['steps_json']) != json.loads(sample_row['steps_json']):
                    raise ValueError(f'Sample mismatch steps for {case_id}')
