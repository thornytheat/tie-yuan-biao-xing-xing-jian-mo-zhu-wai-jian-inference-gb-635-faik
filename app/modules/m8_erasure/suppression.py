"""重放防回灌：撤回生效后，旧样本重放也不能把原值重新写回数据库。

流水线（M1→M5）本身不知道撤回状态；M8 在落库前提供一个过滤层，按盐化哈希
命中抑制规则。抑制规则只存会员号哈希（不存原值），盐随清除单保存，因此：
- 能判断「当前样本里的会员号是否属于已撤回会员」；
- 数据库被脱库后，没有盐也无法把哈希反推成会员号；
- 其他会员的哈希不命中，数据正常落库，不受影响。

过滤只改「原值型字段」，聚合统计需要的去重/计数在 M3 已基于内存中的归一值算完，
落库的只是 sample_value 与隔离/冲突原值，过滤这些不改变计数依据。
"""
from __future__ import annotations

from ... import config
from . import hashing


class SuppressionGuard:
    """加载全部抑制规则，提供按盐哈希的命中判断与落库行清洗。"""

    def __init__(self, store):
        self._requests = {
            row["request_id"]: row for row in store.list_erasure_requests()
            if row["status"] == "done"}
        self._hashes = {row["member_hash"] for row in self._requests.values()}

    @property
    def active(self) -> bool:
        return bool(self._hashes)

    def is_suppressed_member(self, member_id: str, salt_hex: str) -> bool:
        return hashing.member_hash(member_id, salt_hex) in self._hashes

    def suppressed_request(self, member_id: str) -> dict | None:
        """对任一已完成清除单的盐做哈希比对，命中返回该清除单。"""
        for request in self._requests.values():
            if self.is_suppressed_member(member_id, request["salt_hex"]):
                return request
        return None

    def scrub_columns(self, columns: list[dict], member_ids_by_table: dict) -> list[dict]:
        """清洗 save_run 前的 columns 行：只抹撤回会员的样本值，其他会员原样保留。

        member_ids_by_table: {table_lower: set(样本中出现的会员号原值)}，由调用方
        从 intake 解析，避免本模块反向依赖 M1/M2 的内部结构。

        判定按值而不是按整列：
        - 会员号列 / 子表外键列：样本值本身命中抑制哈希才抹；
        - 会员表姓名、手机号列：列样本值与「首个会员号」同行，只有首个会员被撤回才抹，
          保证其他会员排到首行时其姓名/手机号正常落库。
        """
        if not self.active:
            return columns
        first_member = next(iter(sorted(member_ids_by_table.get(
            config.ERASURE_MEMBER_TABLE.lower(), set()))), "")
        first_member_request = (self.suppressed_request(first_member)
                                if first_member else None)
        out = []
        for column in columns:
            table = (column.get("table_name") or "").lower()
            name = (column.get("column_name") or "").lower()
            request = self._value_request(table, name, column.get("sample_value") or "",
                                          first_member_request)
            if request is None:
                out.append(column)
                continue
            cleaned = dict(column)
            sample = cleaned.get("sample_value") or ""
            if sample:
                evidence = dict(cleaned.get("evidence") or {})
                evidence.setdefault("erasure", []).append({
                    "member_hash": request["member_hash"],
                    "value_hash": hashing.value_hash(sample, request["salt_hex"]),
                    "scrubbed_at": _now(),
                    "note": "重放命中撤回抑制，原值未回灌",
                })
                cleaned["sample_value"] = ""
                cleaned["evidence"] = evidence
            out.append(cleaned)
        return out

    def _value_request(self, table: str, column: str, sample_value: str,
                       first_member_request) -> dict | None:
        """按当前样本值判断该格是否属于撤回会员；不属于则返回 None，绝不连坐。"""
        from .scrubber import plan_columns
        if (table, column) not in plan_columns():
            return None
        if column == config.ERASURE_MEMBER_KEY_COLUMN.lower():
            # 会员号列（会员表主键或子表外键）：值即会员号，直接哈希比对
            return self.suppressed_request(sample_value) if sample_value else None
        if table == config.ERASURE_MEMBER_TABLE.lower():
            # 姓名/手机号列：样本值与首行会员同行，首行会员被撤回才抹
            return first_member_request
        return None

    def scrub_quarantine(self, rows: list[dict], member_ids: set[str]) -> list[dict]:
        if not self.active or not member_ids:
            return rows
        suppressed = {mid: self.suppressed_request(mid) for mid in member_ids}
        suppressed = {mid: req for mid, req in suppressed.items() if req is not None}
        if not suppressed:
            return rows
        out = []
        for row in rows:
            text = f"{row.get('raw_value') or ''} {row.get('detail') or ''}"
            if not any(mid and mid in text for mid in suppressed):
                out.append(row)
                continue
            cleaned = dict(row)
            if cleaned.get("raw_value"):
                cleaned["raw_value"] = config.ERASURE_PLACEHOLDER
            detail = cleaned.get("detail") or ""
            if any(mid and mid in detail for mid in suppressed):
                cleaned["detail"] = config.ERASURE_PLACEHOLDER
            out.append(cleaned)
        return out

    def scrub_conflicts(self, rows: list[dict], member_ids: set[str]) -> list[dict]:
        """冲突表 kept/dropped/key_value 命中撤回会员号时脱敏，其余冲突证据保留。"""
        if not self.active or not member_ids:
            return rows
        targets = {mid for mid in member_ids if self.suppressed_request(mid) is not None}
        if not targets:
            return rows
        out = []
        for row in rows:
            if not _row_hits(row, targets):
                out.append(row)
                continue
            cleaned = dict(row)
            if any(mid in (cleaned.get("key_value") or "") for mid in targets):
                cleaned["key_value"] = config.ERASURE_PLACEHOLDER
            for field_name in ("kept", "dropped"):
                payload = cleaned.get(field_name)
                if isinstance(payload, dict):
                    cleaned[field_name] = {
                        key: (config.ERASURE_PLACEHOLDER
                              if isinstance(value, str) and any(mid in value for mid in targets)
                              else value)
                        for key, value in payload.items()}
            out.append(cleaned)
        return out


def _row_hits(row: dict, targets: set[str]) -> bool:
    if any(mid in (row.get("key_value") or "") for mid in targets):
        return True
    for field_name in ("kept", "dropped"):
        payload = row.get(field_name)
        if isinstance(payload, dict) and any(
                isinstance(value, str) and any(mid in value for mid in targets)
                for value in payload.values()):
            return True
    return False


def member_ids_from_intake(intake) -> dict:
    """从 M1 intake 抽取每张表里出现的会员号形态，供抑制过滤定位。

    返回 {table_lower: set(会员号字符串)}；只读取分段行，不修改 intake。
    """
    out: dict[str, set[str]] = {}
    member_section = intake.sections.get(config.ERASURE_MEMBER_TABLE.lower())
    if member_section is not None:
        idx = _header_index(member_section.header, config.ERASURE_MEMBER_KEY_COLUMN)
        if idx >= 0:
            out[config.ERASURE_MEMBER_TABLE.lower()] = {
                (row.cells[idx] or "").strip()
                for row in member_section.rows
                if idx < len(row.cells) and row.cells[idx].strip()}
    ref_section = intake.sections.get(config.ERASURE_REF_TABLE.lower())
    if ref_section is not None:
        idx = _header_index(ref_section.header, config.ERASURE_REF_COLUMN)
        if idx >= 0:
            out[config.ERASURE_REF_TABLE.lower()] = {
                (row.cells[idx] or "").strip()
                for row in ref_section.rows
                if idx < len(row.cells) and row.cells[idx].strip()}
    return out


def _header_index(header: list[str], name: str) -> int:
    target = name.lower()
    for index, item in enumerate(header or []):
        if (item or "").strip().lower() == target:
            return index
    return -1


def _now() -> str:
    import datetime as dt
    from ... import config as cfg
    return dt.datetime.now(cfg.UTC).isoformat(timespec="seconds")
