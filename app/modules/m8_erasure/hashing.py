"""盐化哈希与原值指纹：M8 凭据的不可逆原语。

约束（见 docs/ERASURE.md）：
- 凭据只能证明「某位置曾有一个值、属于同一主体」，不能还原原值；
- 盐只在清除单内存与 erasure_requests.salt_hex 里，不进接口、不进导出；
- 同一清除单内所有批次共用同一盐，跨批次才能按哈希核验同一主体；
- 指纹只记录长度与字符类，不含任何原字符，用于人工核对而不泄露内容。
"""
from __future__ import annotations

import hashlib
import secrets

from ... import config


def new_salt() -> str:
    """256 位随机盐，十六进制保存；每次清除请求独立生成。"""
    return secrets.token_hex(32)


def member_hash(member_id: str, salt_hex: str) -> str:
    """会员号的盐化哈希：撤回后定位主体的唯一凭据，不可逆推会员号。"""
    payload = f"{config.ERASURE_HASH_PREFIX}{_norm(member_id)}:{salt_hex}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def value_hash(value: str, salt_hex: str) -> str:
    """任意原值（姓名、手机号、会员号引用）的盐化哈希，逐格留痕。"""
    payload = f"{config.ERASURE_HASH_PREFIX}value:{_norm(value)}:{salt_hex}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def value_kind(value: str) -> str:
    """字符类指纹：只报类别与长度，不报原字符。

    - digit：纯数字（手机号、会员号多属此类）
    - cjk：含中日韩表意文字（姓名）
    - mixed：数字/字母/符号混合
    - empty：空串
    """
    text = value or ""
    if text == "":
        return "empty"
    if text.isdigit():
        return "digit"
    if any("一" <= ch <= "鿿" for ch in text):
        return "cjk"
    return "mixed"


def fingerprint(value: str) -> dict:
    """不含原值的结构指纹：长度 + 字符类，导出凭据里给人工核对用。"""
    return {"value_length": len(value or ""), "value_kind": value_kind(value or "")}


def _norm(value: str) -> str:
    """归一：会员号在流水线里按编码列保形（补零后），哈希前统一去首尾空白。"""
    return (value or "").strip()
