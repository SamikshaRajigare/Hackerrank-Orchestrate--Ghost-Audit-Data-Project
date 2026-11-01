from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple


class EvidenceLoader:
    def __init__(self, dataset_dir: Path):
        self.dataset_dir = dataset_dir
        self.manifest = None

    def load_manifest(self):
        manifest_path = self.dataset_dir / 'evidence_files.csv'
        self.manifest = __import__('pandas').read_csv(manifest_path)
        return self.manifest

    def load_all(self):
        if self.manifest is None:
            self.load_manifest()
        return self.manifest

    def read_evidence_text(self, file_path: str) -> str:
        path = self.dataset_dir / file_path
        if not path.exists():
            return ''
        try:
            if path.suffix.lower() in {'.json'}:
                with path.open('r', encoding='utf-8', errors='ignore') as fh:
                    data = json.load(fh)
                return json.dumps(data, ensure_ascii=False)
            with path.open('r', encoding='utf-8', errors='ignore') as fh:
                return fh.read()
        except Exception:
            return ''

    def find_matching_file_ids(self, aliases: List[str], user_id: str) -> List[Tuple[str, str, str]]:
        hits: List[Tuple[str, str, str]] = []
        if self.manifest is None:
            self.load_manifest()
        for _, row in self.manifest.iterrows():
            file_id = str(row['file_id'])
            file_path = str(row['file_path'])
            text = self.read_evidence_text(file_path)
            if not text:
                continue
            haystack = text.lower()
            matched = False
            for term in aliases:
                if term and term.lower() in haystack:
                    matched = True
                    break
            if user_id and user_id.lower() in haystack:
                matched = True
            if matched:
                hits.append((file_id, file_path, text[:400]))
        return hits
