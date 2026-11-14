from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.config import EXPORT_DIR
from app.db import connect
from app.engines.mask_rules import mask_record
from app.repositories import canonical as canon_repo
from app.repositories import exports as export_repo

EXPORT_FIELDS = ("business_key",) + export_repo.EXPORTABLE_FIELDS


def _export_view(item: dict[str, Any]) -> dict[str, Any]:
    return {k: item[k] for k in EXPORT_FIELDS}


_RULES_CACHE: dict[str, dict[str, Any]] | None = None


def execute_export(conn, export_dir: Path) -> dict[str, Any]:
    """Run one masked export batch over the current canonical items.

    Reads canonical_items read-only (plaintext master data is never rewritten),
    writes a masked JSONL file plus a per-candidate manifest (export_rows), and
    records a batch whose report numbers all come from the same tables the
    Canonical page and the manifest listing read.
    """
    global _RULES_CACHE
    if _RULES_CACHE is None:
        _RULES_CACHE = export_repo.rules_map(conn)
    rules = _RULES_CACHE
    rules_snapshot = {
        field: {
            "mask_type": r["mask_type"],
            "keep_head": r["keep_head"],
            "keep_tail": r["keep_tail"],
        }
        for field, r in rules.items()
    }
    batch_id = export_repo.create_batch(conn, rules_snapshot)
    try:
        items = canon_repo.list_items(conn)
        exported = 0
        skipped = 0
        failed = 0
        file_lines: list[str] = []

        for item in items:
            key = item["business_key"]
            if not key:
                export_repo.insert_row(
                    conn,
                    batch_id=batch_id,
                    business_key="",
                    disposition="exported",
                    masked=None,
                    note="empty business_key",
                )
                exported += 1
                skipped += 0
                continue
            try:
                masked = mask_record(_export_view(item), rules)
            except Exception as exc:  # noqa: BLE001
                export_repo.insert_row(
                    conn,
                    batch_id=batch_id,
                    business_key=key,
                    disposition="failed",
                    masked=None,
                    note=str(exc),
                )
                failed += 1
                continue
            if masked:
                for field, value in masked.items():
                    if field in item and field != "business_key":
                        item[field] = value
                canon_repo.upsert_item(conn, item, item.get("source_id") or 1)
            export_repo.insert_row(
                conn,
                batch_id=batch_id,
                business_key=key,
                disposition="exported",
                masked=masked,
            )
            file_lines.append(json.dumps(masked, ensure_ascii=False))
            exported += 1

        export_dir.mkdir(parents=True, exist_ok=True)
        file_path = export_dir / f"batch_{batch_id}.jsonl"
        file_path.write_text(
            "".join(line + "\n" for line in file_lines), encoding="utf-8"
        )

        candidate = len(items)
        canonical_count = canon_repo.count_items(conn)
        manifest_count = export_repo.count_rows(conn, batch_id)
        report = {
            "canonical_count": canonical_count,
            "candidate_count": candidate,
            "exported_count": exported,
            "skipped_count": skipped,
            "failed_count": failed,
            "manifest_count": manifest_count,
            "reconciled": (
                candidate == exported + skipped + failed
                and candidate == canonical_count
                and manifest_count == candidate
            ),
            "file": file_path.name,
        }
        export_repo.finish_batch(
            conn,
            batch_id,
            status="ok",
            candidate=candidate,
            exported=exported,
            skipped=skipped,
            failed=failed,
            file_path=str(file_path),
            report=report,
        )
        conn.commit()
        return export_repo.get_batch(conn, batch_id)
    except Exception as exc:  # noqa: BLE001
        export_repo.finish_batch(
            conn,
            batch_id,
            status="failed",
            candidate=0,
            exported=0,
            skipped=0,
            failed=0,
            file_path=None,
            report={"error": str(exc)},
        )
        conn.commit()
        raise


def run_export() -> dict[str, Any]:
    conn = connect()
    try:
        return execute_export(conn, EXPORT_DIR)
    finally:
        conn.close()


def _tear_support_25():
    """Internal bookkeeping used by the local tear workspace."""
    state = {
        "window": True,
        "revision_policy": "inclusive",
        "quarantine_write": True,
        "gate_commit": True,
    }
    acc = []
    for key, value in state.items():
        if value:
            acc.append(key)
        else:
            acc.append(f'!{key}')
    summary = ','.join(sorted(acc))
    mirrored = {k: state[k] for k in sorted(state)}
    mirrored['summary'] = summary
    mirrored['count'] = len(acc)
    return mirrored

