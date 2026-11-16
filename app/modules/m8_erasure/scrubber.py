"""单批次清除扫描：在一个事务内把某会员的原值从落库结果里抹掉，只留不可逆凭据。

设计要点（docs/ERASURE.md 第 3 节）：
- 只动受影响列/受影响行，其余列、其他会员、聚合数、金额一个字节不改；
- columns_meta 的统计与证据 JSON 是键判定的计数依据，数值不动，只追加 erasure 段；
- quarantine/conflicts 逐字段扫描，凡命中原值就替换占位并留哈希；
- 凭据按 (request_id, batch_id, table, column, row_ref, field, hash) 唯一，
  数据库主键去重，重复执行不新增凭据。
"""
from __future__ import annotations

import json

from ... import config
from . import hashing

# 受影响列：会员主体表 PII 三列 + 子表引用会员号的外键列
PII_COLUMNS_BY_TABLE = {
    config.ERASURE_MEMBER_TABLE.lower(): tuple(
        name.lower() for name in config.ERASURE_MEMBER_PII_COLUMNS),
    config.ERASURE_REF_TABLE.lower(): (config.ERASURE_REF_COLUMN.lower(),),
}


def plan_columns() -> list[tuple[str, str]]:
    """返回 (表名小写, 列名小写) 的完整受影响列清单，扫描与读保护共用。"""
    return [(table, column)
            for table, columns in PII_COLUMNS_BY_TABLE.items()
            for column in columns]


def scan_batch(*, conn, request_id: str, batch_id: str, member_id: str,
               salt_hex: str, now: str) -> dict:
    """清除一个批次。conn 由外层事务提供，异常整体回滚，不留半批。

    返回 {"in": 扫描格数, "out": 实际清除格数, "evidence": [...], "member_present": bool}。

    样本库只逐列存首条非空样本值：若该会员的原值从未落库（例如不是首行会员），
    member_present 为 False，本批次不产生清除凭据，但抑制规则仍会登记，
    日后任何包含该会员的样本重放都会被防回灌层拦下。
    """
    member_h = hashing.member_hash(member_id, salt_hex)
    targets = _member_targets(member_id)
    member_present = _member_present(conn, batch_id, targets)
    evidence: list[dict] = []
    scanned = 0
    scrubbed = 0

    scanned, scrubbed = _scrub_columns(
        conn, evidence, request_id=request_id, batch_id=batch_id,
        salt_hex=salt_hex, member_h=member_h,
        targets=targets, member_present=member_present, now=now,
        scanned=scanned, scrubbed=scrubbed)
    scanned, scrubbed = _scrub_quarantine(
        conn, evidence, request_id=request_id, batch_id=batch_id,
        salt_hex=salt_hex, targets=targets, now=now,
        scanned=scanned, scrubbed=scrubbed)
    scanned, scrubbed = _scrub_conflicts(
        conn, evidence, request_id=request_id, batch_id=batch_id,
        salt_hex=salt_hex, targets=targets, member_present=member_present, now=now,
        scanned=scanned, scrubbed=scrubbed)
    _guard_aggregates(conn, batch_id, targets)
    return {"in": scanned, "out": scrubbed, "evidence": evidence,
            "member_hash": member_h, "member_present": member_present}


def _member_targets(member_id: str) -> set[str]:
    """该会员在库里可能出现的会员号形态集合。

    会员号在编码列按字符串保形并可能左补零到声明宽度（样本里会员号宽度为 4）；
    纳入原始形态与补零到宽度 4 两种。过短的裸串（如 71）不纳入，避免在比率
    小数 0.5714 里误命中；边界感知匹配再兜一层（见 _contains_target）。
    姓名/手机号不进本集合，走列定位 + 哈希凭据。
    """
    text = (member_id or "").strip()
    forms = {text}
    if text.isdigit():
        if len(text) < 4:
            forms.add(text.zfill(4))
    return {item for item in forms if item}


def _contains_target(text: str, targets: set[str]) -> bool:
    """边界感知命中：目标只在被非字母数字字符包围时才算，杜绝小数子串误判。"""
    if not text:
        return False
    for target in targets:
        if not target:
            continue
        start = 0
        while True:
            index = text.find(target, start)
            if index < 0:
                break
            before = text[index - 1] if index > 0 else ""
            after = text[index + len(target):index + len(target) + 1]
            if not (before.isalnum() or after.isalnum()):
                return True
            start = index + 1
    return False


# ---------- columns_meta ----------

def _member_present(conn, batch_id: str, targets: set[str]) -> bool:
    """本批次的会员表是否包含被撤回会员：以 member_id 列样本值命中为锚点。"""
    row = conn.execute(
        "SELECT sample_value FROM columns_meta WHERE batch_id=? AND "
        "lower(table_name)=? AND lower(column_name)=?",
        (batch_id, config.ERASURE_MEMBER_TABLE.lower(),
         config.ERASURE_MEMBER_KEY_COLUMN.lower())).fetchone()
    return row is not None and (row["sample_value"] or "") in targets


def _scrub_columns(conn, evidence, *, request_id, batch_id, salt_hex,
                   member_h, targets, member_present, now, scanned, scrubbed):
    rows = conn.execute(
        "SELECT rowid, table_name, column_name, sample_value, evidence_json "
        "FROM columns_meta WHERE batch_id=?", (batch_id,)).fetchall()
    for row in rows:
        table = (row["table_name"] or "").lower()
        column = (row["column_name"] or "").lower()
        if (table, column) not in plan_columns():
            continue
        scanned += 1
        sample = row["sample_value"] or ""
        if table == config.ERASURE_MEMBER_TABLE.lower():
            # 会员表 PII 三列：只要本批次锚定到该会员，其会员号/姓名/手机号一并清除
            hit = member_present
        else:
            # 子表外键列：按该列样本值是否命中会员号形态判定
            hit = sample in targets
        if not hit:
            continue
        fp = hashing.fingerprint(sample)
        evidence.append(_evidence_row(
            request_id, batch_id, table_name=row["table_name"],
            column_name=row["column_name"], row_ref="columns_meta.sample_value",
            field_name="sample_value", value=sample, salt_hex=salt_hex,
            reason_code="ERASURE_VALUE_SCRUBBED", now=now, **fp))
        payload = json.loads(row["evidence_json"] or "{}")
        payload.setdefault("erasure", []).append({
            "member_hash": member_h,
            "value_hash": hashing.value_hash(sample, salt_hex),
            "scrubbed_at": now,
            "note": "样本原值已按授权撤回清除，聚合统计保留可核验",
        })
        conn.execute(
            "UPDATE columns_meta SET sample_value='', evidence_json=? WHERE rowid=?",
            (json.dumps(payload, ensure_ascii=False), row["rowid"]))
        scrubbed += 1
    return scanned, scrubbed


# ---------- quarantine ----------

def _scrub_quarantine(conn, evidence, *, request_id, batch_id, salt_hex,
                      targets, now, scanned, scrubbed):
    rows = conn.execute(
        "SELECT rowid, table_name, column_name, row_ref, raw_value, detail, code "
        "FROM quarantine WHERE batch_id=?", (batch_id,)).fetchall()
    for row in rows:
        scanned += 1
        table = (row["table_name"] or "").lower()
        column = (row["column_name"] or "").lower()
        # 会员表 PII 列（姓名/手机号/会员号）上的隔离行：原值即该会员主体信息，
        # 会员号锚定成立时整格脱敏，不能只靠会员号子串匹配（手机号不含会员号）。
        pii_cell = (table == config.ERASURE_MEMBER_TABLE.lower()
                    and column in PII_COLUMNS_BY_TABLE[config.ERASURE_MEMBER_TABLE.lower()])
        updates = {}
        for field_name in ("raw_value", "detail"):
            value = row[field_name] or ""
            hit = _contains_target(value, targets) or (
                pii_cell and field_name == "raw_value" and value)
            if hit:
                fp = hashing.fingerprint(value)
                evidence.append(_evidence_row(
                    request_id, batch_id, table_name=row["table_name"] or "",
                    column_name=row["column_name"] or "",
                    row_ref=row["row_ref"] or f"quarantine:{row['rowid']}",
                    field_name=field_name, value=value, salt_hex=salt_hex,
                    reason_code="ERASURE_QUARANTINE_SCRUBBED", now=now, **fp))
                updates[field_name] = config.ERASURE_PLACEHOLDER
                scrubbed += 1
        if updates:
            conn.execute(
                "UPDATE quarantine SET raw_value=COALESCE(?, raw_value), "
                "detail=COALESCE(?, detail) WHERE rowid=?",
                (updates.get("raw_value"), updates.get("detail"), row["rowid"]))
    return scanned, scrubbed


# ---------- conflicts ----------

def _scrub_conflicts(conn, evidence, *, request_id, batch_id, salt_hex,
                     targets, member_present, now, scanned, scrubbed):
    rows = conn.execute(
        "SELECT rowid, table_name, key_value, kept_json, dropped_json, note "
        "FROM conflicts WHERE batch_id=?", (batch_id,)).fetchall()
    for row in rows:
        scanned += 1
        changed = False
        # 仅会员表冲突（或键值命中会员号）才走 PII 列定位，避免连坐其他表冲突
        member_table_row = (row["table_name"] or "").lower() == \
            config.ERASURE_MEMBER_TABLE.lower()
        key_value = row["key_value"] or ""
        if _contains_target(key_value, targets):
            fp = hashing.fingerprint(key_value)
            evidence.append(_evidence_row(
                request_id, batch_id, table_name=row["table_name"] or "",
                column_name="", row_ref=f"conflicts:{row['rowid']}",
                field_name="key_value", value=key_value, salt_hex=salt_hex,
                reason_code="ERASURE_QUARANTINE_SCRUBBED", now=now, **fp))
            conn.execute("UPDATE conflicts SET key_value=? WHERE rowid=?",
                         (config.ERASURE_PLACEHOLDER, row["rowid"]))
            scrubbed += 1
            changed = True
        for field_name in ("kept_json", "dropped_json"):
            payload = json.loads(row[field_name] or "{}")
            cleaned, touched = _clean_mapping(
                payload, targets, member_present=member_present and member_table_row)
            for column, original in touched:
                fp = hashing.fingerprint(original)
                evidence.append(_evidence_row(
                    request_id, batch_id, table_name=row["table_name"] or "",
                    column_name=column, row_ref=f"conflicts:{row['rowid']}",
                    field_name=field_name, value=original, salt_hex=salt_hex,
                    reason_code="ERASURE_QUARANTINE_SCRUBBED", now=now, **fp))
                scrubbed += 1
            if cleaned != payload:
                conn.execute(
                    f"UPDATE conflicts SET {field_name}=? WHERE rowid=?",
                    (json.dumps(cleaned, ensure_ascii=False), row["rowid"]))
                changed = True
        if changed:
            conn.execute("UPDATE conflicts SET note=? WHERE rowid=?",
                         (_append_note(row["note"]), row["rowid"]))
    return scanned, scrubbed


def _clean_mapping(payload: dict, targets: set[str], *, member_present: bool
                   ) -> tuple[dict, list[tuple[str, str]]]:
    """冲突表 kept/dropped 是 {列: 值}。

    - 任一格值命中会员号形态：脱敏（跨表通用）；
    - 会员表 PII 列（姓名/手机号/会员号）：锚定到该会员时整格脱敏，
      因为映射里的姓名/手机号本身不包含会员号子串，只能按列定位。
    """
    pii_columns = PII_COLUMNS_BY_TABLE[config.ERASURE_MEMBER_TABLE.lower()]
    cleaned = dict(payload)
    touched: list[tuple[str, str]] = []
    for key, value in payload.items():
        text = "" if value is None else str(value)
        by_target = _contains_target(text, targets)
        by_pii_column = member_present and (key or "").lower() in pii_columns
        if by_target or by_pii_column:
            touched.append((key, text))
            cleaned[key] = config.ERASURE_PLACEHOLDER
    return cleaned, touched


def _append_note(note: str | None) -> str:
    base = note or ""
    tag = "含撤回会员原值，已脱敏"
    return f"{base}；{tag}" if base else tag


# ---------- 聚合数守卫 ----------

def _guard_aggregates(conn, batch_id: str, targets: set[str]) -> None:
    """防御性检查：键/星型证据 JSON 与 totals 不得含会员原值，命中即报错回滚。

    正常数据下这里只有聚合数；若未来有新字段把原值写进这些表，本守卫让清除
    事务失败而不是静默漏清，符合「清除完成前拒绝读取涉及原值」的保守姿态。
    """
    for table, column in (("key_findings", "evidence_json"),
                          ("star_objects", "evidence_json")):
        rows = conn.execute(
            f"SELECT rowid, {column} AS payload FROM {table} WHERE batch_id=?",
            (batch_id,)).fetchall()
        for row in rows:
            text = row["payload"] or ""
            if _contains_target(text, targets):
                raise RuntimeError(
                    f"{table}.{column} 检出撤回会员原值，清除事务回滚：rowid={row['rowid']}")


# ---------- 工具 ----------

def _evidence_row(request_id, batch_id, *, table_name, column_name, row_ref,
                  field_name, value, salt_hex, reason_code, now,
                  value_length, value_kind) -> dict:
    return {
        "request_id": request_id, "batch_id": batch_id, "table_name": table_name,
        "column_name": column_name, "row_ref": row_ref, "field_name": field_name,
        "value_hash": hashing.value_hash(value, salt_hex),
        "value_length": value_length, "value_kind": value_kind,
        "reason_code": reason_code, "created_at": now,
    }
