"""认证蓝图：登录、登出"""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user

from . import db
from .models import User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return _redirect_after_login()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash("用户名或密码错误", "danger")
            return render_template("login.html", username=username)
        if not user.is_active:
            flash("该账号已被停用，请联系管理员", "warning")
            return render_template("login.html", username=username)

        login_user(user, remember=bool(request.form.get("remember")))
        flash(f"欢迎，{user.display_name or user.username}", "success")
        return _redirect_after_login()

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("已退出登录", "info")
    return redirect(url_for("auth.login"))


def _redirect_after_login():
    """根据用户角色跳转：管理员可去 admin，普通用户去门户"""
    target = request.args.get("next")
    if target and target.startswith("/") and not target.startswith("//"):
        return redirect(target)
    if current_user.is_admin:
        return redirect(url_for("admin.index"))
    return redirect(url_for("portal.dashboard"))
