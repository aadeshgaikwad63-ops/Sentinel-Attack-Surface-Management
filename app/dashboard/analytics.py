"""
SentinelASM - Dashboard Analytics
==================================

Read-only aggregation layer for the enterprise dashboard.

This module does NOT touch scanner logic, the AI engines, or the
SQLAlchemy models themselves - it only reads the `scan_data` /
`ai_analysis` JSON columns that `AnalysisPipeline` + `ScannerAdapter`
already compute (see app/scanner/routes.py) and the existing `Log`
audit trail, then shapes them into the structures the dashboard
templates/charts need.

Every number returned here is derived from real rows for the current
user - there is no synthetic/sample data. When a user has no scans
yet, callers get empty collections / None so templates can render a
proper empty state instead of fabricated figures.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone

from app.models import Log, Scan

# Maps a recommendation's numeric priority (see RecommendationEngine)
# to a human severity label, purely for display badges.
_PRIORITY_SEVERITY = {
    1: "Critical",
    2: "High",
    3: "High",
    4: "Medium",
    5: "Medium",
    6: "Low",
}

_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def _aware(dt):
    """Normalize a (possibly naive) datetime to UTC-aware for safe math."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _safe_get(d, *path, default=None):
    cur = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def build_overview(user_id, history_limit=200):
    """
    Build the complete dashboard overview payload for a single user.

    `history_limit` bounds how many of the most recent scans are pulled
    into memory for aggregation (KPI/trend/growth widgets) so a very
    long-lived account doesn't force-load its entire scan history on
    every dashboard render. The lifetime scan count itself is still
    computed with a plain COUNT query, so that figure stays exact.
    """

    total_scans = Scan.query.filter_by(user_id=user_id).count()

    scans = (
        Scan.query.filter_by(user_id=user_id)
        .order_by(Scan.created_at.desc())
        .limit(history_limit)
        .all()
    )

    if not scans:
        return _empty_overview(total_scans)

    # Most-recent scan *per distinct target* - used for "current posture"
    # style aggregates (severity mix, CVE totals, average score) so a
    # target that has been re-scanned 10 times isn't counted 10 times.
    latest_per_target = OrderedDict()
    for s in scans:  # already newest -> oldest
        if s.target not in latest_per_target:
            latest_per_target[s.target] = s

    latest_scan = scans[0]

    kpis = _build_kpis(scans, latest_per_target, total_scans)
    latest = _build_latest(latest_scan)
    trend = _build_trend(scans)
    severity_distribution = _build_severity_distribution(latest_per_target)
    cve_distribution = _build_cve_distribution(latest_per_target)
    open_ports = _build_open_ports(latest_scan)
    top_vulnerabilities = _build_top_vulnerabilities(scans[:5])
    scan_history = _build_scan_history(scans[:10])
    recent_activity = _build_recent_activity(user_id)
    weekly_scan_trend = _build_weekly_scan_trend(scans)
    asset_growth = _build_asset_growth(scans)
    compliance = _build_compliance(latest_per_target)
    assets = _build_assets(latest_per_target)

    return {
        "has_data": True,
        "kpis": kpis,
        "latest": latest,
        "trend": trend,
        "severity_distribution": severity_distribution,
        "cve_distribution": cve_distribution,
        "open_ports": open_ports,
        "top_vulnerabilities": top_vulnerabilities,
        "scan_history": scan_history,
        "recent_activity": recent_activity,
        "weekly_scan_trend": weekly_scan_trend,
        "asset_growth": asset_growth,
        "compliance": compliance,
        "assets": assets,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _empty_overview(total_scans):
    return {
        "has_data": False,
        "kpis": {
            "total_assets": 0,
            "total_scans": total_scans,
            "avg_security_score": None,
            "critical_open": 0,
            "scans_this_week": 0,
            "scans_prior_week": 0,
        },
        "latest": None,
        "trend": [],
        "severity_distribution": {k: 0 for k in _SEVERITY_ORDER},
        "cve_distribution": {"critical": 0, "high": 0, "medium": 0},
        "open_ports": [],
        "top_vulnerabilities": [],
        "scan_history": [],
        "recent_activity": _build_recent_activity_rows([]),
        "weekly_scan_trend": _empty_week_buckets(),
        "asset_growth": [],
        "compliance": {"passing": 0, "total": 0, "percent": None},
        "assets": [],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _build_kpis(scans, latest_per_target, total_scans):
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)
    two_weeks_ago = now - timedelta(days=14)

    scores = [
        _safe_get(s.ai_analysis, "security", "security_score")
        for s in latest_per_target.values()
    ]
    scores = [v for v in scores if isinstance(v, (int, float))]
    avg_security_score = round(sum(scores) / len(scores), 1) if scores else None

    critical_open = sum(
        _safe_get(s.ai_analysis, "risk", "critical_cves", default=0) or 0
        for s in latest_per_target.values()
    )

    scans_this_week = 0
    scans_prior_week = 0
    for s in scans:
        created = _aware(s.created_at)
        if created is None:
            continue
        if created >= week_ago:
            scans_this_week += 1
        elif created >= two_weeks_ago:
            scans_prior_week += 1

    return {
        "total_assets": len(latest_per_target),
        "total_scans": total_scans,
        "avg_security_score": avg_security_score,
        "critical_open": critical_open,
        "scans_this_week": scans_this_week,
        "scans_prior_week": scans_prior_week,
    }


def _build_latest(scan):
    ai = scan.ai_analysis or {}
    return {
        "target": scan.target,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "security_score": _safe_get(ai, "security", "security_score"),
        "grade": _safe_get(ai, "security", "grade"),
        "rating": _safe_get(ai, "security", "rating"),
        "risk_score": _safe_get(ai, "risk", "risk_score"),
        "risk_severity": _safe_get(ai, "risk", "severity"),
        "exposure_score": _safe_get(ai, "exposure", "exposure_score"),
        "attack_surface_score": _safe_get(ai, "attack_surface", "attack_surface_score"),
        "threat_level": _safe_get(ai, "threat", "threat_level"),
        "business_impact": _safe_get(ai, "threat", "business_impact"),
        "summary": ai.get("summary"),
    }


def _build_trend(scans):
    ordered = list(reversed(scans[:12]))  # oldest -> newest, cap 12 points
    points = []
    for s in ordered:
        if not s.created_at:
            continue
        points.append({
            "date": s.created_at.strftime("%b %d"),
            "target": s.target,
            "risk_score": _safe_get(s.ai_analysis, "risk", "risk_score", default=0) or 0,
            "security_score": _safe_get(s.ai_analysis, "security", "security_score", default=0) or 0,
        })
    return points


def _build_severity_distribution(latest_per_target):
    counts = {k: 0 for k in _SEVERITY_ORDER}
    for s in latest_per_target.values():
        severity = _safe_get(s.ai_analysis, "risk", "severity")
        if severity in counts:
            counts[severity] += 1
    return counts


def _build_cve_distribution(latest_per_target):
    critical = high = medium = 0
    for s in latest_per_target.values():
        critical += _safe_get(s.ai_analysis, "risk", "critical_cves", default=0) or 0
        high += _safe_get(s.ai_analysis, "risk", "high_cves", default=0) or 0
        medium += _safe_get(s.ai_analysis, "risk", "medium_cves", default=0) or 0
    return {"critical": critical, "high": high, "medium": medium}


def _build_open_ports(latest_scan):
    ports = _safe_get(latest_scan.scan_data, "ports", default=[]) or []
    counter = defaultdict(int)
    for p in ports:
        if not isinstance(p, dict):
            continue
        label = p.get("service") or f"port {p.get('port', '?')}"
        counter[label] += 1
    ranked = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:8]
    return [{"label": label, "count": count} for label, count in ranked]


def _build_top_vulnerabilities(recent_scans):
    seen_titles = set()
    items = []
    for s in recent_scans:
        recs = _safe_get(s.ai_analysis, "recommendations", default=[]) or []
        for rec in recs:
            title = rec.get("title")
            if not title or title in seen_titles:
                continue
            seen_titles.add(title)
            priority = rec.get("priority", 6)
            items.append({
                "title": title,
                "description": rec.get("description"),
                "impact": rec.get("impact"),
                "priority": priority,
                "severity": _PRIORITY_SEVERITY.get(priority, "Low"),
                "target": s.target,
            })
    items.sort(key=lambda r: r["priority"])
    return items[:8]


def _build_scan_history(recent_scans):
    rows = []
    for s in recent_scans:
        ai = s.ai_analysis or {}
        rows.append({
            "id": s.id,
            "target": s.target,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "risk_score": _safe_get(ai, "risk", "risk_score"),
            "severity": _safe_get(ai, "risk", "severity"),
            "security_score": _safe_get(ai, "security", "security_score"),
            "grade": _safe_get(ai, "security", "grade"),
        })
    return rows


def _build_recent_activity(user_id):
    logs = (
        Log.query.filter_by(user_id=user_id)
        .order_by(Log.created_at.desc())
        .limit(8)
        .all()
    )
    return _build_recent_activity_rows(logs)


def _build_recent_activity_rows(logs):
    return [
        {
            "action": log.action,
            "details": log.details,
            "level": log.level,
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]


def _empty_week_buckets():
    now = datetime.now(timezone.utc)
    buckets = []
    for i in range(6, -1, -1):
        day = now - timedelta(days=i)
        buckets.append({"label": day.strftime("%a"), "count": 0})
    return buckets


def _build_weekly_scan_trend(scans):
    now = datetime.now(timezone.utc)
    day_keys = []
    counts = defaultdict(int)
    for i in range(6, -1, -1):
        day = now - timedelta(days=i)
        key = day.strftime("%Y-%m-%d")
        day_keys.append((key, day.strftime("%a")))

    cutoff = now - timedelta(days=7)
    for s in scans:
        created = _aware(s.created_at)
        if created is None or created < cutoff:
            continue
        key = created.strftime("%Y-%m-%d")
        counts[key] += 1

    return [{"label": label, "count": counts.get(key, 0)} for key, label in day_keys]


def _build_asset_growth(scans):
    """Cumulative distinct-asset count, bucketed weekly over the last 8 weeks."""
    first_seen = {}
    for s in scans:  # newest -> oldest; keep earliest created_at per target
        created = _aware(s.created_at)
        if created is None:
            continue
        if s.target not in first_seen or created < first_seen[s.target]:
            first_seen[s.target] = created

    now = datetime.now(timezone.utc)
    buckets = []
    for i in range(7, -1, -1):
        bucket_end = now - timedelta(weeks=i)
        cumulative = sum(1 for d in first_seen.values() if d <= bucket_end)
        buckets.append({
            "label": bucket_end.strftime("%b %d"),
            "assets": cumulative,
        })
    return buckets


def _build_assets(latest_per_target, limit=8):
    """
    Current posture for each distinct target, most-recently-scanned first -
    powers the dashboard's Asset Overview widget.
    """
    rows = []
    for target, s in latest_per_target.items():
        ai = s.ai_analysis or {}
        rows.append({
            "target": target,
            "security_score": _safe_get(ai, "security", "security_score"),
            "grade": _safe_get(ai, "security", "grade"),
            "risk_score": _safe_get(ai, "risk", "risk_score"),
            "severity": _safe_get(ai, "risk", "severity"),
            "open_ports": _safe_get(ai, "risk", "open_ports", default=0) or 0,
            "critical_cves": _safe_get(ai, "risk", "critical_cves", default=0) or 0,
            "last_scanned": s.created_at.isoformat() if s.created_at else None,
        })
    return rows[:limit]


def _build_compliance(latest_per_target, threshold=75):
    total = len(latest_per_target)
    if total == 0:
        return {"passing": 0, "total": 0, "percent": None}
    passing = sum(
        1
        for s in latest_per_target.values()
        if (_safe_get(s.ai_analysis, "security", "security_score", default=0) or 0) >= threshold
    )
    return {
        "passing": passing,
        "total": total,
        "percent": round(passing / total * 100),
    }
