"""M8 会员撤回授权清除：原值抹除、凭据可核验、重放防回灌、续跑与幂等、读保护。

断言只用样例数据的确定值（会员 0071 = 赵一鸣 / 13800001111），与
docs/ERASURE.md 的规则逐条对应；不依赖随机盐的具体取值。
"""
from __future__ import annotations

import json
import re

import pytest

from app.modules.m5_batches import service as batch_service
from app.modules.m5_batches import state as m5state
from app.modules.m8_erasure import hashing, scrubber, service as erasure_service
from app.modules.m8_erasure.suppression import SuppressionGuard, member_ids_from_intake
from app.modules.m1_ingest import service as m1_service

PII_TOKENS = ("赵一鸣", "13800001111")
MEMBER_ID = "0071"
MEMBER_TABLE = "odl_member"
PII_COLUMNS = ("member_id", "member_name", "phone")


def _column(store, batch_id, table, column):
    for row in store.load_columns(batch_id):
        if row["table_name"] == table and row["column_name"] == column:
            return row
    raise AssertionError(f"列不存在：{table}.{column}")


def _snapshot_keys(store, batch_id):
    return json.dumps(
        [{"t": k["child_table"], "c": k["child_columns"], "i": str(k["inclusion"]),
          "r": str(k["cardinality_ratio"]), "e": k["evidence"]}
         for k in store.load_keys(batch_id)], sort_keys=True, ensure_ascii=False)


def _db_text(store, table):
    import sqlite3
    conn = sqlite3.connect(store.path)
    rows = conn.execute(f"SELECT * FROM {table}").fetchall()
    return json.dumps(rows, ensure_ascii=False, default=str)


# ---------- 原值抹除与保留 ----------

def test_erasure_removes_member_pii_from_all_stored_locations(settings, store, run):
    """会员号/姓名/手机号原值从 columns_meta 抹除，非 PII 列与金额保留。"""
    batch_id = run["batch_id"]
    result = erasure_service.submit(store, MEMBER_ID)
    assert result["status"] == "done"
    for column in PII_COLUMNS:
        assert _column(store, batch_id, MEMBER_TABLE, column)["sample_value"] == ""
    # 子表外键列的会员号同样清除
    assert _column(store, batch_id, "odl_sale_order", "member_id")["sample_value"] == ""
    # 非 PII 列原样保留
    assert _column(store, batch_id, MEMBER_TABLE, "tier")["sample_value"] == "金卡"
    assert _column(store, batch_id, MEMBER_TABLE, "join_date")["sample_value"] == "2023/05/06"
    # 全库扫描：姓名与手机号不再出现在任何业务表
    for table in ("columns_meta", "quarantine", "conflicts", "key_findings",
                  "star_objects", "totals", "manifests"):
        blob = _db_text(store, table)
        assert all(token not in blob for token in PII_TOKENS), table


def test_erasure_keeps_key_judgment_evidence_and_amounts(settings, store, run):
    """键关系判定的聚合依据与订单金额在清除前后逐字相等。"""
    batch_id = run["batch_id"]
    keys_before = _snapshot_keys(store, batch_id)
    totals_before = dict(store.load_totals(batch_id))
    erasure_service.submit(store, MEMBER_ID)
    assert _snapshot_keys(store, batch_id) == keys_before
    totals_after = store.load_totals(batch_id)
    assert totals_after["metric_total"] == totals_before["metric_total"] == "2500.10"
    # 行账不变
    assert totals_after["rows_total"] == totals_before["rows_total"]


def test_erasure_covers_every_historical_batch(settings, store):
    """多个历史批次时，每一个批次都被独立清除并各自留凭据。"""
    seq = {"n": 0}
    original = m5state.new_batch

    def distinct_batch(**kwargs):
        batch = original(**kwargs)
        seq["n"] += 1
        batch["batch_id"] = f"SMHIST{seq['n']:06d}"
        return batch

    m5state.new_batch = distinct_batch
    try:
        batch_service.run(settings=settings, store=store, source="sample",
                          params={"sample_cap": 100})
        batch_service.run(settings=settings, store=store, source="sample",
                          params={"sample_cap": 200}, force=True)
    finally:
        m5state.new_batch = original
    batch_ids = store.list_all_batch_ids()
    assert len(batch_ids) == 2

    result = erasure_service.submit(store, MEMBER_ID)
    assert result["status"] == "done"
    assert result["progress"]["batches_total"] == 2
    assert result["progress"]["batches_done"] == 2
    evidence_batches = {row["batch_id"] for row in
                        store.list_erasure_evidence(result["request"]["request_id"])}
    assert evidence_batches == set(batch_ids)


# ---------- 凭据 ----------

def test_evidence_contains_no_raw_value_but_keeps_verifiable_material(settings, store, run):
    """凭据只有盐化哈希与结构指纹，不含原值、不含盐，但可证明清除发生过。"""
    result = erasure_service.submit(store, MEMBER_ID)
    request_id = result["request"]["request_id"]
    rows = store.list_erasure_evidence(request_id)
    assert rows
    blob = json.dumps(rows, ensure_ascii=False)
    assert all(token not in blob for token in PII_TOKENS)
    assert not re.search(r"(?<![0-9])0071(?![0-9])", blob)
    for row in rows:
        assert len(row["value_hash"]) == 64
        assert row["value_length"] >= 0
        assert row["value_kind"] in ("digit", "cjk", "mixed", "empty")
        assert row["reason_code"] in ("ERASURE_VALUE_SCRUBBED",
                                      "ERASURE_QUARANTINE_SCRUBBED")
    # 接口详情不暴露盐
    detail = erasure_service.status(store, request_id)
    assert "salt_hex" not in json.dumps(detail, ensure_ascii=False)


def test_evidence_csv_export_has_no_raw_value(client, run):
    """凭据 CSV 导出无原值、无盐，可交付审核。"""
    resp = client.post("/api/erasure/members", json={"member_id": MEMBER_ID})
    request_id = resp.json()["request"]["request_id"]
    csv_text = client.get(
        f"/api/erasure/requests/{request_id}/evidence.csv").content.decode("utf-8-sig")
    assert "原值盐化哈希" in csv_text
    assert all(token not in csv_text for token in PII_TOKENS)
    assert not re.search(r"(?<![0-9])0071(?![0-9])", csv_text)


def test_erasure_scrubs_quarantine_and_conflict_rows_without_touching_unrelated(
        settings, store, run):
    """隔离区与冲突表中的会员原值按列定位脱敏，无关隔离/冲突证据原样保留。"""
    batch_id = run["batch_id"]
    with store.connect() as conn:
        conn.execute(
            "INSERT INTO quarantine (batch_id, code, stage, level, table_name, column_name, "
            "row_ref, raw_value, detail) VALUES (?,?,?,?,?,?,?,?,?)",
            (batch_id, "Q_ER_TEST", "profile", "warn", "odl_member", "phone", "row:9",
             "13800001111", f"会员 {MEMBER_ID} 手机号异常"))
        conn.execute(
            "INSERT INTO quarantine (batch_id, code, stage, level, table_name, column_name, "
            "row_ref, raw_value, detail) VALUES (?,?,?,?,?,?,?,?,?)",
            (batch_id, "Q_ER_OK", "contract", "info", "odl_store", "store_code", "row:2",
             "107", "门店编码补零，与会员无关"))
        conn.execute(
            "INSERT INTO conflicts (batch_id, table_name, key_columns_json, key_value, "
            "kept_json, dropped_json, note) VALUES (?,?,?,?,?,?,?)",
            (batch_id, "odl_member", '["member_id"]', MEMBER_ID,
             json.dumps({"member_id": MEMBER_ID, "member_name": "赵一鸣",
                         "phone": "13800001111"}, ensure_ascii=False),
             json.dumps({"member_id": MEMBER_ID, "member_name": "赵一鸣B",
                         "phone": "13800001112"}, ensure_ascii=False),
             "会员冲突"))

    result = erasure_service.submit(store, MEMBER_ID)
    assert result["status"] == "done"

    import sqlite3
    conn = sqlite3.connect(store.path)
    conn.row_factory = sqlite3.Row
    member_q = dict(conn.execute(
        "SELECT raw_value, detail FROM quarantine WHERE code='Q_ER_TEST'").fetchone())
    assert member_q["raw_value"].startswith("〔")
    assert member_q["detail"].startswith("〔")
    other_q = dict(conn.execute(
        "SELECT raw_value FROM quarantine WHERE code='Q_ER_OK'").fetchone())
    assert other_q["raw_value"] == "107"  # 无关隔离行不动
    conflict = dict(conn.execute(
        "SELECT key_value, kept_json, dropped_json FROM conflicts "
        "WHERE table_name='odl_member'").fetchone())
    assert conflict["key_value"].startswith("〔")
    for payload in (conflict["kept_json"], conflict["dropped_json"]):
        assert "赵一鸣" not in payload and "13800001111" not in payload
    # 既有的库存冲突（与会员无关）完整保留
    inventory = dict(conn.execute(
        "SELECT key_value FROM conflicts WHERE table_name='odl_inventory_snapshot'"
    ).fetchone())
    assert inventory["key_value"] == "2026-11-10|0012|00021"
    codes = {row["reason_code"]
             for row in store.list_erasure_evidence(result["request"]["request_id"])}
    assert "ERASURE_QUARANTINE_SCRUBBED" in codes


# --------- 幂等 ----------

def test_repeated_submit_is_idempotent_and_adds_no_evidence(settings, store, run):
    """重复执行不新增清除单、不新增凭据、不重复计数。"""
    first = erasure_service.submit(store, MEMBER_ID)
    request_id = first["request"]["request_id"]
    evidence_n = len(store.list_erasure_evidence(request_id))
    second = erasure_service.submit(store, MEMBER_ID)
    assert second["status"] == "done"
    assert second["code"] == "ERASURE_IDEMPOTENT"
    assert second["request"]["request_id"] == request_id
    assert len(store.list_erasure_evidence(request_id)) == evidence_n
    assert len(store.list_erasure_requests()) == 1


# ---------- 中断续跑 ----------

def test_interrupted_erasure_resumes_from_unfinished_batch(settings, store):
    """中断后已提交批次不回滚，续跑只处理未完成单元，完成后抑制生效。"""
    seq = {"n": 0}
    original = m5state.new_batch

    def distinct_batch(**kwargs):
        batch = original(**kwargs)
        seq["n"] += 1
        batch["batch_id"] = f"SMRES{seq['n']:06d}"
        return batch

    m5state.new_batch = distinct_batch
    try:
        batch_service.run(settings=settings, store=store, source="sample",
                          params={"sample_cap": 100})
        batch_service.run(settings=settings, store=store, source="sample",
                          params={"sample_cap": 200}, force=True)
    finally:
        m5state.new_batch = original

    original_guard = scrubber._guard_aggregates
    calls = {"n": 0}

    def flaky(conn, batch_id, targets):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("模拟第二个批次中断")
        return original_guard(conn, batch_id, targets)

    scrubber._guard_aggregates = flaky
    interrupted = erasure_service.submit(store, MEMBER_ID)
    scrubber._guard_aggregates = original_guard
    assert interrupted["status"] == "interrupted"
    statuses = {u["batch_id"]: u["status"]
                for u in store.list_erasure_units(interrupted["request"]["request_id"])}
    assert "done" in statuses.values() and "running" in statuses.values()
    # 完成前不写抑制规则
    assert store.suppression_hashes() == set()

    resumed = erasure_service.submit(store, MEMBER_ID)
    assert resumed["status"] == "done"
    assert all(u["status"] == "done"
               for u in store.list_erasure_units(resumed["request"]["request_id"]))
    assert len(store.suppression_hashes()) == 1


def test_interrupted_transaction_leaves_no_partial_scrub(settings, store, run):
    """单批次清除异常时事务整体回滚，原值仍在、无半批凭据。"""
    batch_id = run["batch_id"]
    original_guard = scrubber._guard_aggregates

    def boom(*args, **kwargs):
        raise RuntimeError("模拟清除中断")

    scrubber._guard_aggregates = boom
    result = erasure_service.submit(store, MEMBER_ID)
    scrubber._guard_aggregates = original_guard
    assert result["status"] == "interrupted"
    assert _column(store, batch_id, MEMBER_TABLE, "member_name")["sample_value"] == "赵一鸣"
    assert store.list_erasure_evidence(result["request"]["request_id"]) == []


# ---------- 读保护 ----------

def test_reads_of_raw_values_rejected_while_erasure_open(client, run):
    """清除完成前，涉及批次的原值读取接口一律 409；列表与清除台不受影响。"""
    batch_id = run["batch_id"]
    original_guard = scrubber._guard_aggregates

    def boom(*args, **kwargs):
        raise RuntimeError("保持中断")

    scrubber._guard_aggregates = boom
    client.post("/api/erasure/members", json={"member_id": MEMBER_ID})
    scrubber._guard_aggregates = original_guard

    for path in (f"/api/profile?batch_id={batch_id}",
                 f"/api/quarantine?batch_id={batch_id}",
                 f"/api/spec?batch_id={batch_id}",
                 f"/api/batches/{batch_id}",
                 f"/api/model?batch_id={batch_id}"):
        response = client.get(path)
        assert response.status_code == 409
        assert response.json()["error"] == "E_ERASURE_IN_PROGRESS", path
    assert client.get("/api/batches").status_code == 200
    assert client.get("/api/erasure/requests").status_code == 200


# ---------- 重放防回灌 ----------

def test_replay_suppression_keeps_raw_values_out_of_new_batch(settings, store, run):
    """撤回生效后强制重算（旧样本原样重放），受影响会员原值不回灌，金额仍保留。"""
    erasure_service.submit(store, MEMBER_ID)
    intake = m1_service.intake(settings)
    member_ids = member_ids_from_intake(intake)
    assert MEMBER_ID in member_ids[MEMBER_TABLE]

    guard = SuppressionGuard(store)
    assert guard.active
    columns = [
        {"table_name": MEMBER_TABLE, "column_name": "member_name",
         "sample_value": "赵一鸣", "evidence": {}},
        {"table_name": MEMBER_TABLE, "column_name": "tier",
         "sample_value": "金卡", "evidence": {}},
        {"table_name": "odl_sale_order", "column_name": "member_id",
         "sample_value": "0071", "evidence": {}},
        {"table_name": "odl_sale_order", "column_name": "order_amount",
         "sample_value": "1234.50", "evidence": {}},
    ]
    cleaned = guard.scrub_columns(columns, member_ids)
    by_column = {(c["table_name"], c["column_name"]): c["sample_value"] for c in cleaned}
    assert by_column[(MEMBER_TABLE, "member_name")] == ""
    assert by_column[("odl_sale_order", "member_id")] == ""
    assert by_column[(MEMBER_TABLE, "tier")] == "金卡"
    assert by_column[("odl_sale_order", "order_amount")] == "1234.50"
    blob = json.dumps(cleaned, ensure_ascii=False)
    assert all(token not in blob for token in PII_TOKENS)


def test_suppression_does_not_touch_other_members(settings, store, run):
    """抑制规则只命中撤回会员，其他会员哈希不命中、数据正常。"""
    erasure_service.submit(store, MEMBER_ID)
    guard = SuppressionGuard(store)
    request = store.list_erasure_requests()[0]
    assert guard.is_suppressed_member("0071", request["salt_hex"]) is True
    for other in ("0072", "0073", "0074", "0075"):
        assert guard.suppressed_request(other) is None
    # 场景 A：首行是撤回会员 0071 —— 其姓名/手机号样本值被抹
    intake = m1_service.intake(settings)
    ids_with_0071_first = {MEMBER_TABLE: {"0071", "0072"}}
    columns_a = [{"table_name": MEMBER_TABLE, "column_name": "member_name",
                  "sample_value": "赵一鸣", "evidence": {}}]
    assert guard.scrub_columns(columns_a, ids_with_0071_first)[0]["sample_value"] == ""
    # 场景 B：重放样本里首行换成未撤回会员 0072 —— 其姓名/手机号正常落库
    ids_with_0072_first = {MEMBER_TABLE: {"0072", "0073"}}
    columns_b = [{"table_name": MEMBER_TABLE, "column_name": "member_name",
                  "sample_value": "钱多多", "evidence": {}}]
    assert guard.scrub_columns(columns_b, ids_with_0072_first)[0]["sample_value"] == "钱多多"
    # 场景 C：会员号列按值精确命中，未撤回会员的会员号保留
    columns_c = [{"table_name": MEMBER_TABLE, "column_name": "member_id",
                  "sample_value": "0072", "evidence": {}}]
    assert guard.scrub_columns(columns_c, member_ids_from_intake(intake)
                               )[0]["sample_value"] == "0072"


def test_member_without_stored_raw_value_still_gets_suppression(settings, store, run):
    """样本库未逐行落值的会员（如 0072）撤回后无凭据但抑制规则仍登记，重放可拦。"""
    result = erasure_service.submit(store, "0072")
    assert result["status"] == "done"
    assert result["progress"]["evidence_total"] == 0
    unit = store.list_erasure_units(result["request"]["request_id"])[0]
    assert "未扫到" in unit["note"]
    assert len(store.suppression_hashes()) == 1
    guard = SuppressionGuard(store)
    request = store.list_erasure_requests()[0]
    assert guard.is_suppressed_member("0072", request["salt_hex"]) is True


# ---------- 哈希原语 ----------

def test_hashing_is_salted_deterministic_and_unlinkable():
    salt_a, salt_b = hashing.new_salt(), hashing.new_salt()
    assert salt_a != salt_b
    assert hashing.member_hash("0071", salt_a) == hashing.member_hash("0071", salt_a)
    assert hashing.member_hash("0071", salt_a) != hashing.member_hash("0071", salt_b)
    assert hashing.member_hash("0071", salt_a) != hashing.member_hash("0072", salt_a)
    assert hashing.value_hash("0071", salt_a) != hashing.member_hash("0071", salt_a)
    assert hashing.fingerprint("赵一鸣") == {"value_length": 3, "value_kind": "cjk"}
    assert "0071" not in hashing.member_hash("0071", salt_a)


# ---------- 入参校验 ----------

def test_submit_rejects_blank_member_id(client):
    response = client.post("/api/erasure/members", json={"member_id": "  "})
    assert response.status_code == 400
    assert response.json()["error"] == "E_ERASURE_BAD_MEMBER"


def test_erasure_page_and_list_render(client, run):
    assert client.get("/erasure").status_code == 200
    listed = client.get("/api/erasure/requests").json()
    assert listed["total"] == 0
    client.post("/api/erasure/members", json={"member_id": MEMBER_ID})
    listed = client.get("/api/erasure/requests").json()
    assert listed["total"] == 1
    assert listed["rows"][0]["status"] == "done"
    assert "salt" not in json.dumps(listed, ensure_ascii=False)
