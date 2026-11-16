"""M8 编排：按会员执行清除，覆盖历史批次、隔离记录与导出，支持断点续跑与幂等。

流程（docs/ERASURE.md 第 4 节状态机）：
1. 校验会员号；计算盐化哈希，查是否已有清除单；
2. 已 done → 幂等返回，不新增凭据；未 done → 从 pending/running 单元续跑；
3. 每个历史批次一个工作单元，单事务扫描清除并写凭据，失败标 interrupted；
4. 全部单元 done → 清除单 done，写入抑制规则（重放防回灌）；
5. 读保护：未完成期间，受影响列原值读取由 handler 层按 open_erasure_requests 拒绝。
"""
from __future__ import annotations

import datetime as dt

from ... import config, errors, manifest, reasons
from . import hashing, scrubber


def _now() -> str:
    return dt.datetime.now(config.UTC).isoformat(timespec="seconds")


def submit(store, member_id: str) -> dict:
    """提交或续跑一个会员的清除；幂等。"""
    mid = _validate_member_id(member_id)

    # 先用临时盐不行——幂等要求同会员哈希稳定，故先查既有单再决定是否造盐
    existing = _find_existing(store, mid)
    if existing is not None:
        if existing["status"] == "done":
            return _idempotent_payload(store, existing)
        return _resume(store, existing, mid)

    salt_hex = hashing.new_salt()
    member_h = hashing.member_hash(mid, salt_hex)
    request_id = f"ER-{member_h[:16]}"
    created = _now()
    request = {
        "request_id": request_id,
        "erasure_no": manifest.new_run_id(prefix="ER"),
        "member_hash": member_h,
        "salt_hex": salt_hex,
        "status": "running",
        "created_at": created,
        "updated_at": created,
        "finished_at": None,
        "note": reasons.label("ERASURE_REQUEST_OPENED"),
    }
    store.create_erasure_request(request)
    batch_ids = store.list_all_batch_ids()
    for batch_id in batch_ids:
        store.upsert_erasure_unit({"request_id": request_id, "batch_id": batch_id,
                                   "stage": "erasure", "status": "pending"})
    return _run_units(store, request, mid)


def status(store, request_id: str) -> dict:
    request = store.get_erasure_request(request_id)
    if request is None:
        raise errors.NotFound(f"清除单不存在：{request_id}", code="E_NOT_FOUND")
    return _detail(store, request)


def list_requests(store) -> dict:
    rows = []
    for request in store.list_erasure_requests():
        units = store.list_erasure_units(request["request_id"])
        rows.append({
            "request_id": request["request_id"],
            "erasure_no": request["erasure_no"],
            "status": request["status"],
            "status_label": {"running": "运行中", "interrupted": "中断",
                             "done": "已完成"}.get(request["status"], request["status"]),
            "member_hash": request["member_hash"][:16],
            "batches_total": len(units),
            "batches_done": len([u for u in units if u["status"] == "done"]),
            "evidence_total": len(store.list_erasure_evidence(request["request_id"])),
            "created_at": request["created_at"].replace("T", " ")[:19],
            "finished_at": (request["finished_at"] or "").replace("T", " ")[:19],
        })
    return {"rows": rows, "total": len(rows)}


def evidence_rows(store, request_id: str) -> list[dict]:
    request = store.get_erasure_request(request_id)
    if request is None:
        raise errors.NotFound(f"清除单不存在：{request_id}", code="E_NOT_FOUND")
    return store.list_erasure_evidence(request_id)


# ---------- 内部 ----------

def _run_units(store, request: dict, member_id: str) -> dict:
    request_id = request["request_id"]
    salt_hex = request["salt_hex"]
    units = store.pending_erasure_units(request_id)
    interrupted = False
    for unit in units:
        batch_id = unit["batch_id"]
        store.upsert_erasure_unit({**unit, "status": "running", "started_at": _now()})
        try:
            result = _run_one_batch(store, request_id, batch_id, member_id, salt_hex)
        except Exception as exc:  # noqa: BLE001 - 中断要留痕，后续批次可续跑
            store.upsert_erasure_unit({
                **unit, "status": "running", "note": f"{type(exc).__name__}: {exc}"})
            store.update_erasure_request(
                request_id, status="interrupted", updated_at=_now(),
                note=f"批次 {batch_id} 清除中断：{type(exc).__name__}")
            interrupted = True
            break
        store.upsert_erasure_unit({
            **unit, "status": "done", "stage": "erasure",
            "in_count": result["in"], "out_count": result["out"],
            "started_at": unit.get("started_at"), "finished_at": _now(),
            "note": result.get("note") or reasons.label("ERASURE_BATCH_DONE")})
    if interrupted:
        return _detail(store, store.get_erasure_request(request_id))

    pending = store.pending_erasure_units(request_id)
    if pending:
        store.update_erasure_request(request_id, status="interrupted", updated_at=_now(),
                                     note="存在未完成批次，等待续跑")
        return _detail(store, store.get_erasure_request(request_id))

    finished = _now()
    store.update_erasure_request(request_id, status="done", updated_at=finished,
                                 finished_at=finished, note="")
    store.add_suppression(request["member_hash"], request_id, finished)
    return _detail(store, store.get_erasure_request(request_id))


def _run_one_batch(store, request_id, batch_id, member_id, salt_hex) -> dict:
    """单事务：扫描清除 + 凭据落库，任一异常整体回滚。"""
    with store.connect() as conn:
        result = scrubber.scan_batch(
            conn=conn, request_id=request_id, batch_id=batch_id,
            member_id=member_id, salt_hex=salt_hex, now=_now())
        evidence = result.pop("evidence")
        member_present = result.pop("member_present", False)
        result.pop("member_hash", None)
    # 凭据走独立写入，主键去重保证重复执行不新增
    inserted = store.add_erasure_evidence(evidence)
    result["evidence_inserted"] = inserted
    result["member_present"] = member_present
    if not member_present:
        result["note"] = reasons.label("ERASURE_NOTHING_FOUND")
    return result


def _resume(store, request: dict, member_id: str) -> dict:
    store.update_erasure_request(request["request_id"], status="running",
                                 updated_at=_now(), note=reasons.label("ERASURE_RESUMED"))
    return _run_units(store, store.get_erasure_request(request["request_id"]), member_id)


def _idempotent_payload(store, request: dict) -> dict:
    detail = _detail(store, request)
    detail["code"] = "ERASURE_IDEMPOTENT"
    detail["message"] = reasons.label("ERASURE_IDEMPOTENT")
    return detail


def _detail(store, request: dict) -> dict:
    units = store.list_erasure_units(request["request_id"])
    evidence = store.list_erasure_evidence(request["request_id"])
    safe_request = {key: value for key, value in request.items()
                    if key not in ("salt_hex",)}
    return {
        "status": request["status"],
        "code": "",
        "request": safe_request,
        "member_hash": request["member_hash"],
        "units": units,
        "progress": {
            "batches_total": len(units),
            "batches_done": len([u for u in units if u["status"] == "done"]),
            "evidence_total": len(evidence),
            "scrubbed_cells": sum(u["out_count"] for u in units),
        },
        "suppression_active": request["status"] == "done",
    }


def _find_existing(store, member_id: str) -> dict | None:
    """已存在清除单的判定必须在不存储原值的前提下完成：遍历既有单的盐做哈希比对。"""
    for request in store.list_erasure_requests():
        if hashing.member_hash(member_id, request["salt_hex"]) == request["member_hash"]:
            return request
    return None


def _validate_member_id(member_id: str) -> str:
    if not isinstance(member_id, str) or not member_id.strip():
        raise errors.BadRequest("member_id 必须是非空字符串",
                                code="E_ERASURE_BAD_MEMBER")
    text = member_id.strip()
    if len(text) > 64 or any(ch.isspace() for ch in text):
        raise errors.BadRequest("member_id 长度不合法或含空白",
                                code="E_ERASURE_BAD_MEMBER")
    return text
