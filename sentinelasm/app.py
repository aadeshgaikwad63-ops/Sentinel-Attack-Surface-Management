"""
SentinelASM — Frontend preview scaffold
----------------------------------------
This file exists ONLY so the Jinja2 templates below can be rendered and
clicked through in a browser. It intentionally contains no authentication,
RBAC, database, or session logic — that ownership belongs to the backend
team (Member 1). Wire these routes into the real Flask app and replace the
static context dictionaries with real data from the database / risk engine.
"""

from flask import Flask, render_template, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = "dev-preview-only"


@app.route("/login", methods=["GET", "POST"])
def login():
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    return render_template("register.html")


@app.route("/logout")
def logout():
    flash("You have been signed out.")
    return redirect(url_for("login"))


@app.route("/")
@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/assets", methods=["GET", "POST"])
def assets():
    return render_template("assets.html")


@app.route("/scan/new")
def new_scan():
    return render_template("new_scan.html")


@app.route("/scan/results")
def scan_results():
    return render_template("scan_results.html")


@app.route("/scan/vulnerability")
def vulnerability_details():
    return render_template("vulnerability_details.html")


@app.route("/ai-assistant")
def ai_assistant():
    return render_template("ai_assistant.html")


@app.route("/reports")
def reports():
    return render_template("reports.html")


@app.route("/users")
def user_management():
    return render_template("user_management.html")


@app.route("/profile")
def profile():
    return render_template("profile.html")


@app.route("/settings")
def settings():
    return render_template("settings.html")


if __name__ == "__main__":
    app.run(debug=True)
