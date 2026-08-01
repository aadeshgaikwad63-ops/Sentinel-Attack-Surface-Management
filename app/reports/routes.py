import csv
import io

from flask import render_template, Response
from flask_login import login_required
from flask_login import current_user
from flask import jsonify


from app.reports import reports_bp
from app.models.scan import Scan


@reports_bp.route("/")
@login_required
def reports():
    return render_template(
        "reports/reports.html",
        active_page="reports"
    )
@reports_bp.route("/latest")
@login_required
def latest_report():

    latest_scan = (
        Scan.query
        .filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .first()
    )

    if latest_scan is None:
        return jsonify({})

    return jsonify({
        "data": latest_scan.scan_data,
        "ai_analysis": latest_scan.ai_analysis
    })


@reports_bp.route("/export/csv")
@login_required
def export_csv():
    """Export the current user's scan history as a CSV file."""
    scans = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .all()
    )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "Target", "Scanned At", "Risk Score", "Severity",
        "Security Score", "Critical CVEs", "High CVEs", "Open Ports",
    ])
    for scan in scans:
        analysis = scan.ai_analysis or {}
        risk = analysis.get("risk", {})
        security = analysis.get("security", {})
        writer.writerow([
            scan.target,
            scan.created_at.strftime("%Y-%m-%d %H:%M:%S") if scan.created_at else "",
            risk.get("risk_score", ""),
            risk.get("severity", ""),
            security.get("security_score", ""),
            risk.get("critical_cves", 0),
            risk.get("high_cves", 0),
            risk.get("open_ports", 0),
        ])

    output = buffer.getvalue()
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinelasm_scan_history.csv"},
    )


@reports_bp.route("/export/pdf")
@login_required
def export_pdf():
    """Export the latest scan's executive summary as a PDF report."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.pdfgen import canvas as pdf_canvas

    latest_scan = (
        Scan.query.filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .first()
    )

    buffer = io.BytesIO()
    doc = pdf_canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    y = height - inch

    doc.setFont("Helvetica-Bold", 18)
    doc.drawString(inch, y, "SentinelASM - Executive Security Report")
    y -= 0.4 * inch

    doc.setFont("Helvetica", 10)
    if latest_scan is None:
        doc.drawString(inch, y, "No scans have been performed yet.")
    else:
        analysis = latest_scan.ai_analysis or {}
        risk = analysis.get("risk", {})
        security = analysis.get("security", {})
        exposure = analysis.get("exposure", {})
        recommendations = analysis.get("recommendations", [])

        lines = [
            f"Target: {latest_scan.target}",
            f"Scanned at: {latest_scan.created_at.strftime('%Y-%m-%d %H:%M:%S') if latest_scan.created_at else 'N/A'}",
            "",
            f"Risk Score: {risk.get('risk_score', 'N/A')} ({risk.get('severity', 'N/A')})",
            f"Security Score: {security.get('security_score', 'N/A')}/100",
            f"Exposure Score: {exposure.get('exposure_score', 'N/A')}",
            f"Critical CVEs: {risk.get('critical_cves', 0)}",
            f"High CVEs: {risk.get('high_cves', 0)}",
            f"Open Ports: {risk.get('open_ports', 0)}",
            "",
            "Recommendations:",
        ]
        for rec in recommendations:
            lines.append(f"  [Priority {rec.get('priority', '-')}] {rec.get('title', '')}")

        for line in lines:
            doc.drawString(inch, y, line)
            y -= 0.25 * inch
            if y < inch:
                doc.showPage()
                doc.setFont("Helvetica", 10)
                y = height - inch

    doc.save()
    buffer.seek(0)
    return Response(
        buffer.getvalue(),
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=sentinelasm_report.pdf"},
    )