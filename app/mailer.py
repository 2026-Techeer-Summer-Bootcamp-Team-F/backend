# -*- coding: utf-8 -*-
"""이메일 리포트 발송 — 스캔 완료 시 AI 요약 + 리포트 링크를 메일로.

설계(§6 이메일+PDF):
  · provider 어댑터 = RESEND_API_KEY 있으면 Resend HTTP API 발송, 없으면 콘솔 로그
    (로컬 개발은 키 없이도 '보낼 내용'을 눈으로 확인). 코드 한 벌로 로컬·배포 공용.
  · 발송 실패는 절대 스캔을 깨지 않는다 — 호출부(tasks.run_scan)가 try/except로 감쌈.
  · 수신자 = 표적 소유자 user.email(GitHub user:email) → 없으면 scan.config.notify_email
    → 그래도 없으면 발송 스킵(조용히 False).
"""
import html as _html
import logging
import re

import httpx

from .config import settings
from .models import ScanReport, TargetProject, User

log = logging.getLogger(__name__)

RESEND_ENDPOINT = "https://api.resend.com/emails"


# ── 마크다운(요약) → 이메일 HTML (경량; 외부 의존 없음) ─────────────────────
def _md_to_html(md: str) -> str:
    """AI 요약 마크다운을 이메일용 최소 HTML로. 모델 출력이라 먼저 escape 후 포맷
    (표적에서 캐낸 데이터가 <script> 등으로 들어와도 안전). 지원: 제목/굵게/목록/문단."""
    out, ul_open = [], False
    for raw in (md or "").splitlines():
        line = _html.escape(raw.strip())
        line = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", line)  # **굵게**
        if not line:
            if ul_open:
                out.append("</ul>"); ul_open = False
            continue
        if line.startswith("## "):
            if ul_open: out.append("</ul>"); ul_open = False
            out.append(f'<h3 style="margin:18px 0 6px;font-size:15px;color:#e8eaed">{line[3:]}</h3>')
        elif line.startswith("# "):
            if ul_open: out.append("</ul>"); ul_open = False
            out.append(f'<h2 style="margin:18px 0 8px;font-size:17px;color:#e8eaed">{line[2:]}</h2>')
        elif line[:2] in ("- ", "* "):
            if not ul_open:
                out.append('<ul style="margin:6px 0;padding-left:20px">'); ul_open = True
            out.append(f'<li style="margin:3px 0">{line[2:]}</li>')
        else:
            if ul_open: out.append("</ul>"); ul_open = False
            out.append(f'<p style="margin:8px 0;line-height:1.6">{line}</p>')
    if ul_open:
        out.append("</ul>")
    return "\n".join(out)


def build_report_email(project_name: str, scan_id: int, summary_md: str,
                       report_url: str, risk_score=None, breached=None) -> tuple:
    """(subject, html) 생성 — 브랜드 헤더 + 핵심지표 + AI요약 + 리포트 버튼."""
    subject = f"[AI RedTeam] '{project_name}' 스캔 리포트 (#{scan_id})"
    stats = ""
    if risk_score is not None:
        stats += (f'<td style="padding:12px 8px;text-align:center;border:1px solid #e6e6e6">'
                  f'<div style="font-size:11px;color:#888">종합 위험도</div>'
                  f'<div style="font-size:22px;font-weight:700;color:#1a1a1a">{risk_score}'
                  f'<span style="font-size:12px;color:#aaa">/100</span></div></td>')
    if breached is not None:
        col = "#c0392b" if breached else "#2e7d46"
        stats += (f'<td style="padding:12px 8px;text-align:center;border:1px solid #e6e6e6">'
                  f'<div style="font-size:11px;color:#888">침투 성공</div>'
                  f'<div style="font-size:22px;font-weight:700;color:{col}">{breached}건</div></td>')
    stats_row = (f'<table style="width:100%;border-collapse:collapse;margin:18px 0">'
                 f'<tr>{stats}</tr></table>') if stats else ""
    body = _md_to_html(summary_md)
    html = f"""\
<div style="background:#f4f5f7;padding:28px 0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Malgun Gothic',sans-serif">
  <div style="max-width:600px;margin:0 auto;background:#ffffff;border:1px solid #e6e6e6;border-radius:10px;overflow:hidden">
    <div style="padding:22px 26px;border-bottom:2px solid #1a1a1a">
      <div style="color:#888;font-size:11px;letter-spacing:1px;font-weight:600">AI RED TEAM · 자동 모의해킹</div>
      <div style="color:#1a1a1a;font-size:19px;font-weight:700;margin-top:3px">보안 진단 리포트</div>
      <div style="color:#666;font-size:13px;margin-top:4px">{_html.escape(project_name)} · 스캔 #{scan_id}</div>
    </div>
    <div style="padding:8px 26px 24px">
      {stats_row}
      <div style="font-size:13px;font-weight:700;color:#1a1a1a;margin:6px 0 4px;
                  border-bottom:1px solid #ddd;padding-bottom:4px">AI 분석 요약</div>
      <div style="color:#333;font-size:14px">{body}</div>
      <div style="text-align:center;margin:26px 0 6px">
        <a href="{report_url}" style="display:inline-block;background:#1a1a1a;color:#fff;
           text-decoration:none;padding:12px 30px;border-radius:6px;font-weight:600;font-size:14px">
           전체 리포트 보기 →</a>
      </div>
      <div style="color:#aaa;font-size:11px;text-align:center;margin-top:6px">
        링크가 안 열리면: {report_url}</div>
    </div>
  </div>
</div>"""
    return subject, html


# ── provider 어댑터 (ses | resend | console) ────────────────────────────────
def send_email(to: str, subject: str, html: str) -> bool:
    """이메일 1통 발송. EMAIL_PROVIDER로 백엔드 선택(ses/resend/console).
    성공 True / 실패·스킵 False. 예외는 삼켜서 호출부(스캔)를 깨지 않는다."""
    if not to:
        log.info("[mail] 수신주소 없음 → 발송 스킵")
        return False
    provider = (settings.email_provider or "console").lower()
    if provider == "ses":
        return _send_ses(to, subject, html)
    if provider == "resend" and settings.resend_api_key:
        return _send_resend(to, subject, html)
    # console(로컬 개발): 실제 발송 없이 내용만 로그 — provider 미설정/키없음 폴백.
    log.info("[mail] (console·발송안함, provider=%s) to=%s subject=%s\n%s",
             provider, to, subject, html[:800])
    return False


def _send_ses(to: str, subject: str, html: str) -> bool:
    """AWS SES 발송(boto3). 자격증명=기본 체인(env/~/.aws/IAM롤), 리전=ses_region.
    ⚠️ 샌드박스면 from·to 둘 다 verified 여야 함(ProductionAccess 없을 때)."""
    try:
        import boto3
        client = boto3.client("ses", region_name=settings.ses_region)
        kwargs = {
            "Source": settings.email_from,
            "Destination": {"ToAddresses": [to]},
            "Message": {
                "Subject": {"Data": subject, "Charset": "UTF-8"},
                "Body": {"Html": {"Data": html, "Charset": "UTF-8"}},
            },
        }
        if settings.email_reply_to:
            kwargs["ReplyToAddresses"] = [settings.email_reply_to]
        resp = client.send_email(**kwargs)
    except Exception as e:  # noqa: BLE001 - 발송 실패가 스캔을 깨지 않게(botocore 예외 포함)
        log.warning("[mail] SES 발송 실패(무시): %s", e)
        return False
    log.info("[mail] SES 발송 성공 to=%s MessageId=%s", to, resp.get("MessageId"))
    return True


def _send_resend(to: str, subject: str, html: str) -> bool:
    """Resend HTTP API 발송."""
    payload = {"from": settings.email_from, "to": [to],
               "subject": subject, "html": html}
    if settings.email_reply_to:
        payload["reply_to"] = settings.email_reply_to
    try:
        resp = httpx.post(RESEND_ENDPOINT, json=payload, timeout=15,
                          headers={"Authorization": f"Bearer {settings.resend_api_key}"})
    except httpx.RequestError as e:
        log.warning("[mail] Resend 요청 실패(무시): %s", e)
        return False
    if resp.status_code >= 300:
        log.warning("[mail] Resend 응답 오류(status=%s): %s", resp.status_code, resp.text[:300])
        return False
    log.info("[mail] Resend 발송 성공 to=%s", to)
    return True


def _resolve_recipient(db, scan) -> str:
    """수신주소 결정 — scan.config.notify_email(수동 지정) 우선 → 표적 소유자 user.email."""
    cfg = scan.config or {}
    if cfg.get("notify_email"):
        return cfg["notify_email"]
    target = db.get(TargetProject, scan.target_id)
    if not target:
        return ""
    user = db.get(User, target.user_id)
    return (user.email if user and user.email else "")


def notify_scan_report(db, scan, summary_md: str, *, force: bool = False,
                       to: str = "") -> bool:
    """스캔 완료 리포트 메일 발송(자동 훅·수동 재발송 공용).

    force=False(자동): scan.config.email_notify(opt-in) 켜졌을 때만.
    force=True(수동 엔드포인트): opt-in 무시하고 무조건 시도.
    to: 지정하면 그 주소로(수동 발송 시 사용자 입력) — 없으면 자동 결정.
    """
    cfg = scan.config or {}
    # opt-out: 기본은 발송. config.email_notify=false 로 명시할 때만 끔(수신자 있으면 자동).
    if not force and cfg.get("email_notify") is False:
        return False
    to = to or _resolve_recipient(db, scan)
    if not to:
        log.info("[mail] scan=%s 수신주소 없음 → 스킵", scan.scan_id)
        return False
    target = db.get(TargetProject, scan.target_id)
    project_name = (target.project_name if target else None) or f"scan #{scan.scan_id}"
    report_url = f"{settings.frontend_url.rstrip('/')}/report/{scan.scan_id}"
    row = db.query(ScanReport).filter(ScanReport.scan_id == scan.scan_id).first()
    subject, html = build_report_email(
        project_name, scan.scan_id, summary_md, report_url,
        risk_score=(round(row.risk_score) if row and row.risk_score is not None else None),
        breached=(row.breached_attempts if row else None))
    return send_email(to, subject, html)
