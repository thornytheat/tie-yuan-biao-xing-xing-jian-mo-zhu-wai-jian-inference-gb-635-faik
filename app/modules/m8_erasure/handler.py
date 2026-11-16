"""M8 入口：会员撤回授权清除接口、凭据导出与清除台页面。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response

from ... import errors
from ...web import Ctx, get_ctx, render
from . import csv_out, service

router = APIRouter(tags=["M8 授权撤回清除"])


@router.post("/api/erasure/members")
def api_submit(payload: dict | None = None, ctx: Ctx = Depends(get_ctx)) -> dict:
    payload = payload or {}
    member_id = payload.get("member_id")
    if not isinstance(member_id, str) or not member_id.strip():
        raise errors.BadRequest("member_id 必须是非空字符串",
                                code="E_ERASURE_BAD_MEMBER")
    return service.submit(ctx.store, member_id)


@router.get("/api/erasure/requests")
def api_list(ctx: Ctx = Depends(get_ctx)) -> dict:
    return service.list_requests(ctx.store)


@router.get("/api/erasure/requests/{request_id}")
def api_status(request_id: str, ctx: Ctx = Depends(get_ctx)) -> dict:
    return service.status(ctx.store, request_id)


@router.get("/api/erasure/requests/{request_id}/evidence.csv")
def api_evidence_csv(request_id: str, ctx: Ctx = Depends(get_ctx)) -> Response:
    rows = service.evidence_rows(ctx.store, request_id)
    body = csv_out.encode(csv_out.to_csv_text(rows, request_id))
    return Response(content=body, media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition":
                             f'attachment; filename="starmodel-erasure-{request_id}.csv"'})


@router.get("/erasure")
def page_erasure(request: Request, ctx: Ctx = Depends(get_ctx)):
    payload = service.list_requests(ctx.store)
    return render(request, "erasure.html", page="erasure",
                  page_title="授权撤回清除", payload=payload, batch=None)
