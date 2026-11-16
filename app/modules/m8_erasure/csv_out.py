"""M8 凭据导出：清除凭据 CSV，只含盐化哈希与结构指纹，不含任何原值、不含盐。"""
from __future__ import annotations

import csv
import io

HEADERS = ("清除单", "批次", "表", "列", "行定位", "字段", "原值盐化哈希",
           "原值长度", "字符类", "原因码", "清除时间")


def to_csv_text(rows: list[dict], request_id: str) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(HEADERS)
    for row in rows:
        writer.writerow([
            request_id,
            row.get("batch_id") or "",
            row.get("table_name") or "",
            row.get("column_name") or "",
            row.get("row_ref") or "",
            row.get("field_name") or "",
            row.get("value_hash") or "",
            row.get("value_length") if row.get("value_length") is not None else "",
            row.get("value_kind") or "",
            row.get("reason_code") or "",
            (row.get("created_at") or "").replace("T", " ")[:19],
        ])
    return buffer.getvalue()


def encode(text: str) -> bytes:
    return text.encode("utf-8-sig")
