#!/usr/bin/env python3
"""Evidence-first deletion audit for the Ghost Data Still Exists challenge."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import unicodedata
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"

SYSTEM_BY_PREFIX = {
    "account": "account_service",
    "tombstone": "account_service",
    "search": "search_service",
    "analytics": "analytics_platform",
    "telemetry": "analytics_platform",
    "support": "support_platform",
    "export": "export_service",
    "data_flow": "integration_service",
    "backup": "backup_service",
    "audit_record": "security_service",
    "security": "security_service",
    "marketing": "marketing_service",
    "email_delivery": "email_delivery_service",
    "cache": "cache_service",
    "object": "object_storage",
}

CATEGORY_BY_PREFIX = {
    "account": "USER_PROFILE",
    "tombstone": "ACCOUNT_TOMBSTONE",
    "search": "SEARCH_INDEX_ENTRY",
    "analytics": "ANALYTICS_PROFILE",
    "telemetry": "PRODUCT_TELEMETRY",
    "support": "SUPPORT_MESSAGE",
    "export": "USER_EXPORT",
    "data_flow": "DATA_FLOW",
    "backup": "BACKUP_ARCHIVE",
    "audit_record": "SECURITY_AUDIT_LOG",
    "security": "SECURITY_AUDIT_LOG",
    "marketing": "MARKETING_PROFILE",
    "email_delivery": "EMAIL_DELIVERY_LOG",
    "cache": "CACHE_ENTRY",
    "object": "SUPPORT_ATTACHMENT",
}

SYSTEM_BY_TABLE = {
    "customer_profiles": "account_service",
    "customer_profiles_primary": "account_service",
    "customer_profiles_failover_replica": "account_service",
    "customer_data_primary": "account_service",
    "customer_data_read_replica": "account_service",
    "customer_data_replica_ap_south": "account_service",
    "customer_data_replica_eu_west": "account_service",
    "customer_data_reporting_replica": "account_service",
    "customer_data_failover_replica": "account_service",
    "customer_search_documents": "search_service",
    "search_documents_primary": "search_service",
    "customer_analytics_profiles": "analytics_platform",
    "support_records": "support_platform",
    "customer_exports": "export_service",
    "connector_subscriptions": "integration_service",
    "backup_restore_entries": "backup_service",
    "security_audit_records": "security_service",
}

CATEGORY_BY_TABLE = {
    "customer_profiles": "USER_PROFILE",
    "customer_profiles_primary": "USER_PROFILE",
    "customer_profiles_failover_replica": "USER_PROFILE",
    "customer_data_primary": "USER_PROFILE",
    "customer_data_read_replica": "USER_PROFILE",
    "customer_data_replica_ap_south": "USER_PROFILE",
    "customer_data_replica_eu_west": "USER_PROFILE",
    "customer_data_reporting_replica": "USER_PROFILE",
    "customer_data_failover_replica": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "search_documents_primary": "SEARCH_INDEX_ENTRY",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "support_records": "SUPPORT_MESSAGE",
    "customer_exports": "USER_EXPORT",
    "connector_subscriptions": "DATA_FLOW",
    "backup_restore_entries": "BACKUP_ARCHIVE",
    "security_audit_records": "SECURITY_AUDIT_LOG",
}

VALID_SYSTEMS = set(SYSTEM_BY_PREFIX.values()) | {
    "backup_restore_service",
    "legal_service",
    "support_storage_service",
    "privacy_treatment_service",
    "identity_service",
    "object_storage",
}

VALID_CATEGORIES = {
    "USER_PROFILE",
    "SECONDARY_IDENTIFIER",
    "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY",
    "SUPPORT_MESSAGE",
    "SUPPORT_ATTACHMENT",
    "ANALYTICS_PROFILE",
    "PRODUCT_TELEMETRY",
    "USER_EXPORT",
    "MARKETING_PROFILE",
    "EMAIL_DELIVERY_LOG",
    "SECURITY_AUDIT_LOG",
    "LEGAL_HOLD_RECORD",
    "BACKUP_ARCHIVE",
    "ACCOUNT_TOMBSTONE",
    "DATA_FLOW",
}

DIRECT_FIELDS = {
    "email",
    "customer_email",
    "owner_email",
    "requester_email",
    "full_name",
    "name",
    "requester_name",
    "display_name",
    "phone",
    "requester_phone",
    "owner_phone",
    "email_hash",
}

OPERATION_ORDER = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": 0,
        "REPORT_EXPOSED_PII": 1,
        "REPORT_ACTIVE_DATA_FLOW": 2,
        "REPORT_RESTORE_RISK": 3,
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": 0,
        "BLOCK_RESTORE": 1,
        "DELETE_RECORD": 2,
        "REDACT_RECORD": 3,
        "ANONYMIZE_RECORD": 4,
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": 0,
        "VERIFY_RECORD_PRESENT": 1,
        "VERIFY_RECORD_REDACTED": 2,
        "VERIFY_RECORD_ANONYMIZED": 3,
        "VERIFY_DATA_FLOW_DISABLED": 4,
        "VERIFY_RESTORE_BLOCKED": 5,
    },
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def parse_time(value: Any) -> datetime | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in {"null", "none", "n/a"}:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def normalize_text(value: Any) -> str:
    return unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode().casefold()


def normalize_email(value: Any) -> str:
    return str(value or "").strip().casefold()


def normalize_phone(value: Any) -> str:
    return re.sub(r"\D", "", str(value or ""))


def flatten_mapping(value: Any, prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(child, dict):
                flattened.update(flatten_mapping(child, name))
            elif not isinstance(child, list):
                flattened[name.casefold()] = child
    return flattened


@dataclass
class Observation:
    system_id: str
    resource_id: str
    category: str
    evidence_id: str
    captured_at: datetime | None
    available_at: datetime | None = None
    attrs: dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""
    existence: str = "PRESENT"


def infer_resource(resource_id: str, source: str = "", table: str = "") -> tuple[str, str]:
    name = resource_id.casefold()
    for prefix, system in SYSTEM_BY_PREFIX.items():
        if name.startswith(prefix + "_"):
            return system, CATEGORY_BY_PREFIX[prefix]
    if table:
        return SYSTEM_BY_TABLE.get(table, "unknown_system"), CATEGORY_BY_TABLE.get(table, "UNKNOWN")
    source_lower = source.casefold()
    if "support" in source_lower:
        return "support_platform", "SUPPORT_MESSAGE"
    if "connector" in source_lower:
        return "integration_service", "DATA_FLOW"
    return "unknown_system", "UNKNOWN"


def find_resource_id(text: str) -> str:
    match = re.search(
        r"\b(account|tombstone|search|analytics|telemetry|support|export|data_flow|backup|"
        r"audit_record|security|marketing|email_delivery|cache|object)_\d+\b",
        text,
        re.IGNORECASE,
    )
    return match.group(0) if match else ""


def infer_existence(attrs: dict[str, Any], raw_text: str, category: str) -> str:
    values = {str(key).casefold(): str(value).strip().casefold() for key, value in attrs.items()}
    text = raw_text.casefold()
    for key in ("status", "state", "result", "lookup_result", "record_state", "deletion_state"):
        value = values.get(key, "")
        if any(term in value for term in ("not_found", "not found", "absent", "missing", "deleted", "404")):
            return "ABSENT"
        if any(term in value for term in ("identifiable", "present", "found", "active", "hit", "enabled")):
            return "PRESENT"
    status_code = values.get("status_code", values.get("http_status", ""))
    if status_code == "404":
        return "ABSENT"
    for key in ("rows", "row_count", "total_hits"):
        if values.get(key) == "0":
            return "ABSENT"
    if re.search(r"\b(result|status|profile_lookup_completed)\s*=\s*(not_found|miss|absent)\b", text):
        return "ABSENT"
    if "profile=null" in text or "profile: null" in text:
        return "ABSENT"
    return "PRESENT"


def add_record(
    records: list[Observation],
    *,
    evidence_id: str,
    captured_at: datetime | None,
    resource_id: str,
    attrs: dict[str, Any],
    raw_text: str,
    source: str,
    table: str = "",
    system: str = "",
    category: str = "",
    existence: str | None = None,
    available_at: datetime | None = None,
) -> None:
    if not resource_id:
        resource_id = find_resource_id(raw_text)
    if not resource_id:
        return
    inferred_system, inferred_category = infer_resource(resource_id, source, table)
    system_id = system if system in VALID_SYSTEMS else inferred_system
    data_category = category.upper() if category.upper() in VALID_CATEGORIES else inferred_category
    event_name = str(attrs.get("event") or "").casefold()
    if (
        data_category == "ANALYTICS_PROFILE" and "contact_lookup" in event_name
    ) or (
        data_category == "SUPPORT_MESSAGE"
        and (
            "contact_query" in event_name
            or str(attrs.get("source", "")).casefold() == "legacy_contact_index"
        )
    ):
        data_category = "SECONDARY_IDENTIFIER"
    state = existence or infer_existence(attrs, raw_text, data_category)
    records.append(
        Observation(
            system_id=system_id,
            resource_id=resource_id,
            category=data_category,
            evidence_id=evidence_id,
            captured_at=captured_at,
            available_at=available_at or captured_at,
            attrs=attrs,
            raw_text=raw_text,
            existence=state,
        )
    )


def parse_pdf(path: Path) -> str:
    """Extract basic ReportLab PDF text without third-party dependencies."""
    data = path.read_bytes()
    objects: dict[int, bytes] = {
        int(match.group(1)): match.group(2)
        for match in re.finditer(rb"(\d+)\s+\d+\s+obj(.*?)endobj", data, re.S)
    }

    def stream_for(obj: bytes) -> bytes:
        start = obj.find(b"stream")
        end = obj.rfind(b"endstream")
        if start < 0 or end < 0 or end < start:
            return b""
        start += len(b"stream")
        if obj[start : start + 2] == b"\r\n":
            start += 2
        elif obj[start : start + 1] in {b"\r", b"\n"}:
            start += 1
        payload = obj[start:end].rstrip(b"\r\n")
        if b"ASCII85Decode" in obj:
            try:
                payload = base64.a85decode(payload, adobe=True)
            except ValueError:
                return b""
        if b"FlateDecode" in obj:
            try:
                return zlib.decompress(payload)
            except zlib.error:
                return b""
        return payload

    cmap_by_obj: dict[int, dict[int, str]] = {}
    for object_id, obj in objects.items():
        cmap = stream_for(obj)
        if b"begincmap" not in cmap:
            continue
        mapping: dict[int, str] = {}
        for block in re.findall(rb"beginbfchar(.*?)endbfchar", cmap, re.S):
            for source, target in re.findall(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", block):
                try:
                    mapping[int(source, 16)] = bytes.fromhex(target.decode()).decode("utf-16-be")
                except (ValueError, UnicodeDecodeError):
                    continue
        for block in re.findall(rb"beginbfrange(.*?)endbfrange", cmap, re.S):
            for start, end, target in re.findall(
                rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", block
            ):
                first, last, base = int(start, 16), int(end, 16), int(target, 16)
                width = len(target) // 2
                for code in range(first, min(last, first + 4096) + 1):
                    try:
                        mapping[code] = (base + code - first).to_bytes(width, "big").decode("utf-16-be")
                    except (OverflowError, UnicodeDecodeError):
                        continue
        cmap_by_obj[object_id] = mapping

    font_object_by_name: dict[str, int] = {}
    for obj in objects.values():
        for name, object_id in re.findall(rb"/(F\d+(?:\+\d+)?)\s+(\d+)\s+\d+\s+R", obj):
            font_object_by_name[name.decode()] = int(object_id)
    cmap_by_font: dict[str, dict[int, str]] = {}
    for font_name, font_object_id in font_object_by_name.items():
        font_object = objects.get(font_object_id, b"")
        unicode_ref = re.search(rb"/ToUnicode\s+(\d+)\s+\d+\s+R", font_object)
        if unicode_ref:
            cmap_by_font[font_name] = cmap_by_obj.get(int(unicode_ref.group(1)), {})

    extracted: list[str] = []
    for obj in objects.values():
        content = stream_for(obj)
        if b"BT" not in content:
            continue
        current_font = ""
        for token in re.finditer(
            rb"/(F\d+(?:\+\d+)?)\s+[\d.]+\s+Tf|<([0-9A-Fa-f]+)>\s*Tj|\(((?:\\.|[^\\)])*)\)\s*Tj|"
            rb"\[(.*?)\]\s*TJ",
            content,
            re.S,
        ):
            if token.group(1):
                current_font = token.group(1).decode()
                continue
            mapping = cmap_by_font.get(current_font, {})
            hex_text = token.group(2)
            literal = token.group(3)
            array = token.group(4)
            if hex_text:
                raw = bytes.fromhex(hex_text.decode())
                extracted.append("".join(mapping.get(code, chr(code)) for code in raw))
            elif literal is not None:
                decoded = re.sub(rb"\\([()\\])", rb"\1", literal)
                extracted.append("".join(mapping.get(code, chr(code)) for code in decoded))
            elif array is not None:
                for item in re.findall(rb"<([0-9A-Fa-f]+)>|\(((?:\\.|[^\\)])*)\)", array, re.S):
                    if item[0]:
                        raw = bytes.fromhex(item[0].decode())
                    else:
                        raw = re.sub(rb"\\([()\\])", rb"\1", item[1])
                    extracted.append("".join(mapping.get(code, chr(code)) for code in raw))
    return "\n".join(extracted)


def parse_log_line(line: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in re.findall(r"([\w.]+)=([^\s]+)", line):
        result[key.casefold()] = value.strip(",;\"'")
    if "|" in line:
        parts = [part.strip() for part in line.strip().strip("-").split("|")]
        if len(parts) >= 5:
            result.update(
                {
                    "event_time": parts[0],
                    "system": parts[1],
                    "resource_id": parts[2],
                    "category": parts[3],
                    "status": parts[4],
                    "email": parts[5] if len(parts) > 5 else "",
                }
            )
    return result


def build_observations(dataset: Path) -> list[Observation]:
    manifest = {
        row["file_path"].replace("/", "\\").casefold(): row
        for row in read_csv(dataset / "evidence_files.csv")
    }
    observations: list[Observation] = []
    evidence_root = dataset / "evidence"
    tesseract = shutil.which("tesseract")
    unreadable_images: list[Path] = []
    for path in sorted(evidence_root.rglob("*")):
        if not path.is_file():
            continue
        relative = str(path.relative_to(dataset)).replace("/", "\\").casefold()
        manifest_row = manifest.get(relative)
        if not manifest_row:
            continue
        evidence_id = manifest_row["file_id"]
        captured_at = parse_time(manifest_row["captured_at"])

        if path.suffix.casefold() == ".sql":
            connection = sqlite3.connect(":memory:")
            try:
                connection.executescript(path.read_text(encoding="utf-8", errors="replace"))
                tables = connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
                for (table,) in tables:
                    if table == "snapshot_scope":
                        continue
                    columns = [
                        row[1] for row in connection.execute(f'PRAGMA table_info("{table}")')
                    ]
                    for row in connection.execute(f'SELECT * FROM "{table}"'):
                        attrs = dict(zip(columns, row))
                        rid = str(attrs.get("resource_id") or "")
                        add_record(
                            observations,
                            evidence_id=evidence_id,
                            captured_at=captured_at,
                            resource_id=rid,
                            attrs=attrs,
                            raw_text=json.dumps(attrs, ensure_ascii=False, default=str),
                            source=str(path),
                            table=table,
                            available_at=captured_at,
                        )
            except sqlite3.Error as exc:
                raise RuntimeError(f"Could not parse SQLite evidence {path}: {exc}") from exc
            finally:
                connection.close()
            continue

        if path.suffix.casefold() == ".json":
            try:
                document = json.loads(path.read_text(encoding="utf-8-sig"))
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Could not parse JSON evidence {path}: {exc}") from exc

            def walk(node: Any, context: dict[str, Any]) -> None:
                if isinstance(node, dict):
                    inherited = {**context, **{k: v for k, v in node.items() if not isinstance(v, (dict, list))}}
                    if node.get("resource_id"):
                        attrs = flatten_mapping(node)
                        attrs.update({k.casefold(): v for k, v in inherited.items()})
                        add_record(
                            observations,
                            evidence_id=evidence_id,
                            captured_at=parse_time(
                                attrs.get("observed_at")
                                or attrs.get("updated_at")
                                or attrs.get("captured_at")
                                or attrs.get("exported_at")
                            )
                            or captured_at,
                            resource_id=str(node["resource_id"]),
                            attrs=attrs,
                            raw_text=json.dumps(node, ensure_ascii=False, default=str),
                            source=str(path),
                            system=str(inherited.get("data_store") or inherited.get("system") or ""),
                            category=str(inherited.get("data_category") or ""),
                            available_at=captured_at,
                        )
                    for child in node.values():
                        walk(child, inherited)
                elif isinstance(node, list):
                    for child in node:
                        walk(child, context)

            walk(document, {})
            continue

        if path.suffix.casefold() == ".pdf":
            text = parse_pdf(path)
            resource_ids = sorted(set(re.findall(
                r"\b(?:account|tombstone|search|analytics|telemetry|support|export|data_flow|"
                r"backup|audit_record|marketing|email_delivery|object)_\d+\b",
                text,
                re.IGNORECASE,
            )))
            emails = sorted(set(re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text)))
            category = (
                "SUPPORT_ATTACHMENT"
                if re.search(r"\b(?:attachment|identity document|attached file)\b", text, re.IGNORECASE)
                else ""
            )
            for resource_id in resource_ids:
                add_record(
                    observations,
                    evidence_id=evidence_id,
                    captured_at=captured_at,
                    resource_id=resource_id,
                    attrs={"emails": " ".join(emails), "document_text": text},
                    raw_text=text,
                    source=str(path),
                    category=category,
                    available_at=captured_at,
                )
            continue

        if path.suffix.casefold() == ".png":
            if not tesseract:
                unreadable_images.append(path)
                continue
            result = subprocess.run(
                [tesseract, str(path), "stdout"],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
            )
            if result.returncode:
                detail = result.stderr.strip() or f"exit code {result.returncode}"
                raise RuntimeError(f"OCR failed for {path}: {detail}")
            text = result.stdout
            resource_ids = sorted(set(re.findall(
                r"\b(?:account|tombstone|search|analytics|telemetry|support|export|data_flow|"
                r"backup|audit_record|marketing|email_delivery|object)_\d+\b",
                text,
                re.IGNORECASE,
            )))
            emails = sorted(set(re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text)))
            for resource_id in resource_ids:
                add_record(
                    observations,
                    evidence_id=evidence_id,
                    captured_at=captured_at,
                    resource_id=resource_id,
                    attrs={"emails": " ".join(emails), "image_text": text},
                    raw_text=text,
                    source=str(path),
                    available_at=captured_at,
                )
            continue

        if path.suffix.casefold() in {".log", ".txt"}:
            trace_context: dict[str, dict[str, Any]] = {}
            trace_text: dict[str, list[str]] = {}
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                attrs = parse_log_line(line)
                resource_id = str(attrs.get("resource_id") or find_resource_id(line))
                trace_id = str(attrs.get("trace_id") or "")
                if trace_id and not resource_id:
                    trace_context.setdefault(trace_id, {}).update(attrs)
                    trace_text.setdefault(trace_id, []).append(line)
                    continue
                if not resource_id:
                    continue
                if trace_id and trace_id in trace_context:
                    merged_attrs = dict(trace_context[trace_id])
                    merged_attrs.update(attrs)
                    attrs = merged_attrs
                    line = "\n".join(trace_text[trace_id] + [line])
                time_match = re.search(r"\b20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z?\b", line)
                event_time = attrs.get("event_time") or (time_match.group(0) if time_match else "")
                add_record(
                    observations,
                    evidence_id=evidence_id,
                    captured_at=parse_time(event_time) or captured_at,
                    resource_id=resource_id,
                    attrs=attrs,
                    raw_text=line,
                    source=str(path),
                    system=str(attrs.get("system") or attrs.get("service") or ""),
                    category=str(attrs.get("category") or ""),
                    available_at=captured_at,
                )
    if unreadable_images:
        print(
            f"Warning: OCR unavailable (install Tesseract to inspect {len(unreadable_images)} PNG evidence files).",
            file=sys.stderr,
        )
    return observations


def collect_identity_context(
    dataset: Path,
) -> tuple[dict[str, dict[str, str]], dict[str, list[dict[str, str]]]]:
    identity_rows = {row["user_id"]: row for row in read_csv(dataset / "user_identities.csv")}
    audits_by_user: dict[str, list[dict[str, str]]] = {}
    for row in read_csv(dataset / "user_audit_log.csv"):
        audits_by_user.setdefault(row["user_id"], []).append(row)
    return identity_rows, audits_by_user


def is_deletion_request(request_text: str) -> bool:
    text = normalize_text(request_text)
    negative_patterns = (
        r"\bnot\s+(?:asking|requesting|seeking)\s+(?:for\s+)?(?:account\s+)?deletion\b",
        r"\bnot\s+(?:a\s+)?request\s+to\s+(?:delete|erase|remove)\b",
        r"\bdo\s+not\s+(?:delete|erase|remove|close)\b",
        r"\bdon't\s+(?:delete|erase|remove|close)\b",
        r"\bkeep\s+(?:the\s+)?account\b",
        r"\bleave\s+(?:the\s+)?account\s+active\b",
        r"\bstill\s+(?:need|use|want)\s+(?:the\s+)?account\b",
        r"\bwithout\s+(?:deleting|erasing|closing)\b",
        r"\bnot\s+(?:asking|requesting)\s+for\s+(?:an?\s+)?erasure\b",
        r"\bno\s+estoy\s+solicitando\s+(?:la\s+)?eliminacion\b",
        r"\b(?:only|just)\s+(?:remove|stop|unsubscribe)\b.{0,50}\b(?:marketing|promotional|newsletter|emails?)\b",
        r"\bremove\s+me\s+from\s+(?:the\s+)?(?:marketing|promotional|mailing)\s+(?:list|emails?)\b",
    )
    if any(re.search(pattern, text) for pattern in negative_patterns):
        return False
    positive_patterns = (
        r"\bdelet[a-z]*\b",
        r"\beras[a-z]*\b",
        r"\b(?:remove|removing|removed)\b.{0,80}\b(?:account|profile|personal\s+data|personal\s+details|records?|copies|search\s+result|information|identity\s+document)\b",
        r"\b(?:account|profile|personal\s+data|records?|information)\b.{0,80}\b(?:remove|removed|erase|erased|delete|deleted)\b",
        r"\bclose\s+(?:(?:my|the|this)\s+)?account\b",
        r"\baccount\s+closure\b",
        r"\bpermanent(?:ly)?\s+(?:account\s+)?delet",
        r"\bno\s+longer\s+need\s+(?:this\s+)?account\b.{0,120}\bremove\b",
        r"\baccount\s+(?:itself\s+)?(?:is\s+)?gone\b.{0,100}\b(?:deleted-account|personal\s+details|remove)\b",
        r"\b(?:don'?t|do not|do not want)\b.{0,100}\b(?:any|my|personal)?\s*(?:data|information|traces?)\s+left\b",
        r"\b(?:account|profile)\b.{0,100}\b(?:gone|deleted|removed)\b.{0,120}\b(?:remaining\s+records|cannot\s+identify|confirm|verify|check)\b",
        r"\b(?:elimin|borr|suprim|effac|suppression|exclus)[a-z]*\b",
        r"\bencerrar\s+minha\s+conta\b",
        r"\bexcluir\b",
        r"\bapagar\s+(?:minha\s+)?conta\b",
    )
    return any(re.search(pattern, text) for pattern in positive_patterns)


def get_record_values(observation: Observation) -> tuple[set[str], set[str], set[str]]:
    values = {str(k).split(".")[-1].casefold(): v for k, v in observation.attrs.items()}
    emails: set[str] = set()
    phones: set[str] = set()
    hashes: set[str] = set()
    for key, value in values.items():
        if value is None:
            continue
        text = str(value).strip()
        if "email" in key and "hash" not in key:
            emails.update(normalize_email(e) for e in re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text))
            if "@" in text:
                emails.add(normalize_email(text))
        elif "phone" in key:
            digits = normalize_phone(text)
            if digits:
                phones.add(digits)
        elif key in {"matched_value", "identifier_value"}:
            emails.update(normalize_email(e) for e in re.findall(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text))
            digits = normalize_phone(text)
            if digits and len(digits) >= 7:
                phones.add(digits)
        elif "hash" in key:
            hashes.add(text.casefold())
    return emails, phones, hashes


def record_belongs_to_user(
    observation: Observation,
    user_ids: set[str],
    identifiers: dict[str, set[str]],
    linked_resources: dict[str, set[str]],
) -> bool:
    if linked_resources.get(observation.resource_id, set()) & user_ids:
        return True
    text = observation.raw_text.casefold()
    for field_name in ("user_id", "customer_reference", "subject_reference", "owner_user_id", "user_reference"):
        value = observation.attrs.get(field_name)
        if value and str(value).casefold() in user_ids:
            return True
    if any(re.search(rf"\b{re.escape(user_id)}\b", text) for user_id in user_ids):
        return True
    lookup_key = observation.attrs.get("lookup_key")
    for key in ("lookup_key", "match_key", "subject_key", "subject_ref", "correlation_key"):
        key_value = observation.attrs.get(key)
        if key_value and normalize_email(key_value) in {
            normalize_email(value) for value in identifiers["email"]
        }:
            return True
        if key_value and str(key_value).casefold() in user_ids:
            return True
    emails, phones, hashes = get_record_values(observation)
    if emails & {normalize_email(value) for value in identifiers["email"]}:
        return True
    if phones & {normalize_phone(value) for value in identifiers["phone"] if normalize_phone(value)}:
        return True
    if hashes & {value.casefold() for value in identifiers["hash"]}:
        return True
    all_ids = {value.casefold() for values in identifiers.values() for value in values}
    if any(identifier and identifier in text for identifier in all_ids):
        return True
    return False


def active_at(observation: Observation, audit_at: datetime) -> bool:
    if observation.available_at is not None and observation.available_at > audit_at:
        return False
    return observation.captured_at is None or observation.captured_at <= audit_at


def latest_observations(
    observations: Iterable[Observation], audit_at: datetime
) -> list[Observation]:
    same_file: dict[tuple[str, str, str], Observation] = {}
    for observation in observations:
        if not active_at(observation, audit_at):
            continue
        file_key = (observation.system_id, observation.resource_id, observation.evidence_id)
        prior = same_file.get(file_key)
        if prior is None:
            same_file[file_key] = observation
            continue
        prior_time = prior.captured_at or datetime.min.replace(tzinfo=timezone.utc)
        current_time = observation.captured_at or datetime.min.replace(tzinfo=timezone.utc)
        newer, older = (observation, prior) if current_time >= prior_time else (prior, observation)
        merged_attrs = dict(older.attrs)
        merged_attrs.update(newer.attrs)
        same_file[file_key] = Observation(
            system_id=newer.system_id,
            resource_id=newer.resource_id,
            category=newer.category,
            evidence_id=newer.evidence_id,
            captured_at=newer.captured_at,
            available_at=newer.available_at,
            attrs=merged_attrs,
            raw_text=f"{older.raw_text}\n{newer.raw_text}",
            existence=newer.existence,
        )

    latest: dict[tuple[str, str], Observation] = {}
    for observation in same_file.values():
        key = (observation.system_id, observation.resource_id)
        prior = latest.get(key)
        if prior is None or (observation.captured_at or datetime.min.replace(tzinfo=timezone.utc)) >= (
            prior.captured_at or datetime.min.replace(tzinfo=timezone.utc)
        ):
            latest[key] = observation
    return list(latest.values())


def status_for_record(observation: Observation, audit_at: datetime) -> tuple[str, str] | None:
    category = observation.category
    attrs = {str(key).split(".")[-1].casefold(): value for key, value in observation.attrs.items()}
    direct_values = {
        key: value
        for key, value in attrs.items()
        if key in DIRECT_FIELDS and value is not None and str(value).strip().casefold() not in {"", "null", "none"}
    }

    if category == "USER_PROFILE" and str(attrs.get("account_status", "")).casefold() in {
        "deleted",
        "tombstone",
        "deletion_tombstone",
    }:
        category = "ACCOUNT_TOMBSTONE"
    if category == "DATA_FLOW":
        enabled = str(attrs.get("enabled", attrs.get("active", ""))).casefold()
        state = "ACTIVE" if enabled in {"1", "true", "yes", "enabled"} else "DISABLED"
        return ("flow", state)
    if category == "BACKUP_ARCHIVE":
        restorable = str(
            attrs.get(
                "restore_allowed",
                attrs.get("restore_enabled", attrs.get("eligible", "")),
            )
        ).casefold()
        blocked = str(attrs.get("deletion_block", "")).casefold() in {"1", "true", "yes"}
        if blocked:
            restorable = "false"
        state = "ACTIVE" if restorable in {"1", "true", "yes", "enabled", "active"} else "BLOCKED"
        return ("backup", state)
    if category == "SECURITY_AUDIT_LOG":
        retention = parse_time(attrs.get("retention_until"))
        return ("retained", "PRESENT" if retention is None or retention >= audit_at else "ABSENT")
    if category == "LEGAL_HOLD_RECORD":
        active = str(attrs.get("active", attrs.get("hold_status", ""))).casefold()
        return ("retained", "PRESENT" if active not in {"false", "0", "released", "inactive"} else "ABSENT")
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        if observation.existence == "ABSENT":
            return ("record", "ABSENT")
        emails, phones, hashes = get_record_values(observation)
        if direct_values or emails or phones or hashes:
            return ("record", "EXPOSED")
        return ("record", "ANONYMIZED")
    if category in {"SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"}:
        if observation.existence == "ABSENT":
            return ("record", "ABSENT")
        emails, phones, hashes = get_record_values(observation)
        if direct_values or emails or phones or hashes:
            return ("record", "EXPOSED")
        return ("record", "REDACTED")
    if category == "UNKNOWN":
        return None
    if observation.existence == "ABSENT":
        return ("record", "ABSENT")
    return ("record", "PRESENT")


def step(
    phase: str,
    system_id: str,
    resource_id: str,
    operation: str,
    state: str,
    evidence_id: str,
) -> dict[str, Any]:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def order_steps(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    steps.sort(
        key=lambda item: (
            {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}[item["phase"]],
            OPERATION_ORDER[item["phase"]][item["operation"]],
            item["system_id"],
            item["resource_id"],
        )
    )
    for index, item in enumerate(steps, start=1):
        item["step_no"] = index
    return steps


def build_case(
    request: dict[str, str],
    identity_rows: dict[str, dict[str, str]],
    audits_by_user: dict[str, list[dict[str, str]]],
    observations: list[Observation],
    linked_resources: dict[str, set[str]],
) -> dict[str, Any]:
    text = request.get("request_text", "")
    if not is_deletion_request(text):
        return {"case_id": request["case_id"], "deletion_status": "NOT_APPLICABLE", "steps": []}

    audit_at = parse_time(request.get("audit_at")) or datetime.max.replace(tzinfo=timezone.utc)
    supplied_email = normalize_email(request.get("email", ""))
    user_ids: set[str] = set()
    identifiers = {"email": {request.get("email", "")}, "phone": set(), "name": set(), "hash": set()}
    eligible_audits: dict[str, list[dict[str, str]]] = {}
    for user_id in set(identity_rows) | set(audits_by_user):
        audit_rows = audits_by_user.get(user_id, [])
        eligible = [
            row for row in audit_rows
            if (event_time := parse_time(row.get("event_time"))) is not None and event_time <= audit_at
        ]
        eligible_audits[user_id] = eligible
        row = identity_rows.get(user_id, {})
        if normalize_email(row.get("email")) == supplied_email:
            user_ids.add(user_id)
        for audit in eligible:
            if audit.get("field_name", "").casefold() == "email" and supplied_email in {
                normalize_email(audit.get("old_value")),
                normalize_email(audit.get("new_value")),
            }:
                user_ids.add(user_id)

    for user_id in user_ids:
        row = identity_rows.get(user_id, {})
        identity_time = parse_time(row.get("updated_at"))
        if identity_time is None or identity_time <= audit_at:
            for field_name, kind in (
                ("email", "email"),
                ("phone", "phone"),
                ("name", "name"),
                ("email_hash", "hash"),
            ):
                if row.get(field_name):
                    identifiers[kind].add(row[field_name])
        for audit in eligible_audits.get(user_id, []):
            field_name = audit.get("field_name", "").casefold()
            kind = "hash" if field_name == "email_hash" else field_name
            if kind in identifiers:
                identifiers[kind].update(
                    value for value in (audit.get("old_value", ""), audit.get("new_value", "")) if value
                )

    case_links: dict[str, set[str]] = {}
    for resource_id, references in linked_resources.items():
        for reference in references:
            linked_user, separator, linked_time = reference.partition("|")
            timestamp = parse_time(linked_time) if separator else None
            if timestamp is None or timestamp <= audit_at:
                case_links.setdefault(resource_id, set()).add(linked_user)

    matching = [
        observation
        for observation in latest_observations(observations, audit_at)
        if record_belongs_to_user(observation, user_ids, identifiers, case_links)
    ]
    profile_records = [
        observation
        for observation in matching
        if observation.category == "USER_PROFILE"
    ]
    if len(profile_records) > 1:
        newest_profile_time = max(
            observation.captured_at or datetime.min.replace(tzinfo=timezone.utc)
            for observation in profile_records
        )
        matching = [
            observation
            for observation in matching
            if observation.category != "USER_PROFILE"
            or (observation.captured_at or datetime.min.replace(tzinfo=timezone.utc)) == newest_profile_time
        ]
    # Keep only the strongest record-level view for duplicate IDs; the latest source
    # capture is used by latest_observations and raw evidence IDs remain attached.

    findings: list[dict[str, Any]] = []
    remediations: list[dict[str, Any]] = []
    verifications: dict[tuple[str, str, str], dict[str, Any]] = {}
    incomplete = False

    for observation in matching:
        kind_state = status_for_record(observation, audit_at)
        if not kind_state:
            continue
        record_type, state = kind_state
        system_id, resource_id, evidence_id = (
            observation.system_id,
            observation.resource_id,
            observation.evidence_id,
        )

        if record_type == "flow":
            operation = "VERIFY_DATA_FLOW_DISABLED"
            if state == "ACTIVE":
                incomplete = True
                findings.append(step("FINDING", system_id, resource_id, "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", evidence_id))
                remediations.append(step("REMEDIATION", system_id, resource_id, "DISABLE_DATA_FLOW", "DISABLED", ""))
            else:
                verifications[(operation, system_id, resource_id)] = step(
                    "VERIFICATION", system_id, resource_id, operation, "DISABLED", evidence_id
                )
            if state == "ACTIVE":
                verifications[(operation, system_id, resource_id)] = step(
                    "VERIFICATION", system_id, resource_id, operation, "DISABLED", ""
                )
            continue

        if record_type == "backup":
            operation = "VERIFY_RESTORE_BLOCKED"
            if state == "ACTIVE":
                incomplete = True
                findings.append(step("FINDING", system_id, resource_id, "REPORT_RESTORE_RISK", "ACTIVE", evidence_id))
                remediations.append(step("REMEDIATION", system_id, resource_id, "BLOCK_RESTORE", "BLOCKED", ""))
                verifications[(operation, system_id, resource_id)] = step(
                    "VERIFICATION", system_id, resource_id, operation, "BLOCKED", ""
                )
            else:
                verifications[(operation, system_id, resource_id)] = step(
                    "VERIFICATION", system_id, resource_id, operation, "BLOCKED", evidence_id
                )
            continue

        if record_type == "retained":
            if state == "PRESENT":
                verifications[("VERIFY_RECORD_PRESENT", system_id, resource_id)] = step(
                    "VERIFICATION",
                    system_id,
                    resource_id,
                    "VERIFY_RECORD_PRESENT",
                    "PRESENT",
                    evidence_id,
                )
            continue

        if state == "PRESENT":
            incomplete = True
            findings.append(
                step("FINDING", system_id, resource_id, "REPORT_REMAINING_RECORD", "PRESENT", evidence_id)
            )
            remediations.append(
                step("REMEDIATION", system_id, resource_id, "DELETE_RECORD", "ABSENT", "")
            )
            verifications[("VERIFY_RECORD_ABSENT", system_id, resource_id)] = step(
                "VERIFICATION", system_id, resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", ""
            )
        elif state == "EXPOSED":
            incomplete = True
            findings.append(step("FINDING", system_id, resource_id, "REPORT_EXPOSED_PII", "PRESENT", evidence_id))
            if observation.category == "ANALYTICS_PROFILE" or observation.category == "PRODUCT_TELEMETRY":
                remediations.append(
                    step("REMEDIATION", system_id, resource_id, "ANONYMIZE_RECORD", "ANONYMIZED", "")
                )
                verify_operation, verify_state = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
            else:
                remediations.append(
                    step("REMEDIATION", system_id, resource_id, "REDACT_RECORD", "REDACTED", "")
                )
                verify_operation, verify_state = "VERIFY_RECORD_REDACTED", "REDACTED"
            verifications[(verify_operation, system_id, resource_id)] = step(
                "VERIFICATION", system_id, resource_id, verify_operation, verify_state, ""
            )
        elif state == "ABSENT":
            verifications[("VERIFY_RECORD_ABSENT", system_id, resource_id)] = step(
                "VERIFICATION", system_id, resource_id, "VERIFY_RECORD_ABSENT", "ABSENT", evidence_id
            )
        elif state == "REDACTED":
            verifications[("VERIFY_RECORD_REDACTED", system_id, resource_id)] = step(
                "VERIFICATION", system_id, resource_id, "VERIFY_RECORD_REDACTED", "REDACTED", evidence_id
            )
        elif state == "ANONYMIZED":
            verifications[("VERIFY_RECORD_ANONYMIZED", system_id, resource_id)] = step(
                "VERIFICATION", system_id, resource_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", evidence_id
            )

    if not matching:
        # Without an identity link or record-level evidence there is no defensible
        # basis for asserting deletion completion.
        incomplete = True

    if incomplete:
        # A compliant retained security record is part of the proof for an incomplete
        # case too. All future verification steps must have empty evidence references.
        for verification in verifications.values():
            verification["evidence_id"] = ""
        all_steps = findings + remediations + list(verifications.values())
        status = "INCOMPLETE"
    else:
        # Complete cases contain only verifications backed by evidence at audit time.
        all_steps = [
            item
            for item in verifications.values()
            if item["evidence_id"]
        ]
        status = "COMPLETE" if all_steps else "INCOMPLETE"

    return {
        "case_id": request["case_id"],
        "deletion_status": status,
        "steps": order_steps(all_steps),
    }


def load_resource_links(dataset: Path) -> dict[str, set[str]]:
    links: dict[str, set[str]] = {}
    with (dataset / "system_activity.csv").open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            if row["event_type"] != "LINK_RESOURCE_IDENTITY":
                continue
            resource = row["resource_id"]
            details = row.get("details", "")
            user_match = re.search(r"\buser_\d+\b", details, re.IGNORECASE)
            if user_match:
                # The timestamp is retained so each case can apply its own cutoff.
                links.setdefault(resource, set()).add(
                    f"{user_match.group(0).casefold()}|{row.get('event_time', '')}"
                )
    return links


def write_output(rows: list[dict[str, Any]], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        for row in sorted(rows, key=lambda item: item["case_id"]):
            writer.writerow(
                {
                    "case_id": row["case_id"],
                    "deletion_status": row["deletion_status"],
                    "steps_json": json.dumps(row["steps"], ensure_ascii=False, separators=(",", ":")),
                }
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DATASET, help="Directory containing challenge CSV files")
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Request CSV to audit (defaults to dataset/deletion_requests.csv)",
    )
    parser.add_argument("--output", type=Path, default=ROOT / "output.csv", help="Destination CSV path")
    args = parser.parse_args(argv)

    dataset = args.dataset.resolve()
    input_path = (args.input or dataset / "deletion_requests.csv").resolve()
    if not input_path.is_file():
        parser.error(f"request CSV not found: {input_path}")
    requests = read_csv(input_path)
    required = {"case_id", "email", "audit_at", "request_text"}
    if requests and not required.issubset(requests[0]):
        parser.error(f"request CSV must include columns: {', '.join(sorted(required))}")

    observations = build_observations(dataset)
    identities, audits_by_user = collect_identity_context(dataset)
    resource_links = load_resource_links(dataset)
    results = [
        build_case(request, identities, audits_by_user, observations, resource_links)
        for request in requests
    ]
    write_output(results, args.output.resolve())
    print(f"Wrote {len(results)} audited cases to {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, sqlite3.Error) as error:
        print(f"Audit failed: {error}", file=sys.stderr)
        raise SystemExit(1)
