"""Auth routes: login, register, logout."""

from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_user, logout_user, login_required, current_user

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("scan.dashboard"))

    if request.method == "POST":
        User     = current_app.config["USER_MODEL"]
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user     = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user, remember=True)
            return redirect(url_for("scan.dashboard"))
        flash("Invalid email or password.", "error")

    return render_template("login.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("scan.dashboard"))

    if request.method == "POST":
        User = current_app.config["USER_MODEL"]
        db   = current_app.config["DB"]

        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if not email or not password:
            flash("Email and password are required.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        elif len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
        else:
            user = User(email=email, plan="free")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user, remember=True)
            flash("Account created. You are on the free plan — 1 scan per month.", "success")
            return redirect(url_for("scan.dashboard"))

    return render_template("register.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
