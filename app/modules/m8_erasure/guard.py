"""读保护：清除完成前，涉及撤回会员的原值读取一律拒绝。

在 profile/quarantine/conflicts/spec 等读路径上调用；聚合数、金额、其他列
正常返回。判定依据是 erasure_units 中该批次存在未 done 的清除单。
"""
from __future__ import annotations

from ... import errors


def assert_batch_readable(store, batch_id: str) -> None:
    """批次上有未完成清除单时，拒绝读取（409），督促等清除完成。"""
    open_requests = store.open_erasure_requests_for_batch(batch_id)
    if open_requests:
        raise errors.Conflict(
            f"批次 {batch_id} 存在进行中的授权撤回清除，原值读取已暂停",
            code="E_ERASURE_IN_PROGRESS",
            detail={"request_ids": [r["request_id"] for r in open_requests]})
