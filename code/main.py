from __future__ import annotations

import json
import importlib
import importlib.util
import sys
from pathlib import Path

import pandas as pd  # pyright: ignore[reportMissingModuleSource]

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIR = Path(__file__).resolve().parent
PACKAGE_NAME = 'deletion_audit'

package_spec = importlib.util.spec_from_file_location(
    PACKAGE_NAME,
    PACKAGE_DIR / '__init__.py',
    submodule_search_locations=[str(PACKAGE_DIR)],
)
if package_spec is None or package_spec.loader is None:
    raise ImportError(f'Unable to load application package from {PACKAGE_DIR}')

package = importlib.util.module_from_spec(package_spec)
sys.modules[PACKAGE_NAME] = package
package_spec.loader.exec_module(package)

AuditAgent = importlib.import_module(f'{PACKAGE_NAME}.audit_agent').AuditAgent
validate_output_df = importlib.import_module(
    f'{PACKAGE_NAME}.output_validator'
).validate_output_df


def main() -> None:
    agent = AuditAgent(ROOT)
    output_df = agent.generate_output()
    requests_df = pd.read_csv(ROOT / 'dataset' / 'deletion_requests.csv')
    sample_df = pd.read_csv(ROOT / 'dataset' / 'sample_output.csv')
    validate_output_df(output_df, requests_df, sample_df)
    output_path = ROOT / 'output.csv'
    output_df.to_csv(output_path, index=False)
    print(f'Wrote {len(output_df)} rows to {output_path}')


if __name__ == '__main__':
    main()
