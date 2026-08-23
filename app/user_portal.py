"""用户门户蓝图：选择 RAM Role -> 生成 SAMLResponse -> POST 到阿里云 ACS"""
from base64 import b64encode

from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, current_app, abort)
from flask_login import login_required, current_user

from .models import UserRole
from .saml import build_saml_response, SamlError

portal_bp = Blueprint("portal", __name__)


@portal_bp.route("/")
@login_required
def dashboard():
    # 列出当前用户绑定的、且角色仍启用的绑定关系
    bindings = (UserRole.query
                .filter_by(user_id=current_user.id)
                .join(UserRole.role)
                .filter_by(is_active=True)
                .order_by(UserRole.created_at.desc())
                .all())
    return render_template("portal/dashboard.html", bindings=bindings)


@portal_bp.route("/role/<int:role_binding_id>/console", methods=["POST"])
@login_required
def saml_login(role_binding_id):
    """生成 SAML Response 并通过 auto-submit form POST 到阿里云 ACS"""
    binding = UserRole.query.filter_by(
        id=role_binding_id, user_id=current_user.id
    ).first()
    if binding is None or not binding.role or not binding.role.is_active:
        abort(404)

    role = binding.role
    session_name = current_user.username

    try:
        saml_xml = build_saml_response(
            username=session_name,
            role_arn=role.arn,
        )
    except SamlError as e:
        flash(f"生成 SAML 登录凭证失败：{e}", "danger")
        return redirect(url_for("portal.dashboard"))

    saml_b64 = b64encode(saml_xml.encode("utf-8")).decode("ascii")
    acs_url = current_app.config["SAML_ACS_URL"]

    return render_template(
        "portal/saml_post.html",
        role=role, acs_url=acs_url, saml_response=saml_b64,
    )
