"""管理后台蓝图：用户 CRUD、RAM Role CRUD、用户-角色绑定管理"""
from flask import (Blueprint, render_template, redirect, url_for,
                   request, flash, abort, jsonify, current_app)
from flask_login import login_required, current_user

from . import db
from .models import User, RamRole, UserRole

admin_bp = Blueprint("admin", __name__)


def _require_admin():
    if not current_user.is_admin:
        abort(403)


@admin_bp.before_request
def _gate_admin():
    _require_admin()


@admin_bp.route("/")
def index():
    stats = {
        "users": User.query.count(),
        "roles": RamRole.query.count(),
        "bindings": UserRole.query.count(),
        "admins": User.query.filter_by(is_admin=True).count(),
    }
    return render_template("admin/dashboard.html", stats=stats)


# ============================================================
# 用户管理
# ============================================================
@admin_bp.route("/users")
def user_list():
    q = request.args.get("q", "").strip()
    query = User.query
    if q:
        query = query.filter(User.username.like(f"%{q}%") | User.display_name.like(f"%{q}%"))
    users = query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=users, q=q)


@admin_bp.route("/users/new", methods=["GET", "POST"])
def user_create():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        display_name = request.form.get("display_name", "").strip()
        email = request.form.get("email", "").strip()
        is_admin = bool(request.form.get("is_admin"))
        is_active = bool(request.form.get("is_active", True))

        if not username or not password:
            flash("用户名和密码不能为空", "danger")
            return render_template("admin/user_form.html", mode="create",
                                   user=None, form=request.form)
        if User.query.filter_by(username=username).first():
            flash("用户名已存在", "danger")
            return render_template("admin/user_form.html", mode="create",
                                   user=None, form=request.form)

        u = User(username=username, display_name=display_name or None,
                 email=email or None, is_admin=is_admin, is_active=is_active)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash(f"用户 {username} 创建成功", "success")
        return redirect(url_for("admin.user_edit", user_id=u.id))

    return render_template("admin/user_form.html", mode="create",
                           user=None, form=None)


@admin_bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
def user_edit(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == "POST":
        action = request.form.get("action")

        if action == "profile":
            user.display_name = request.form.get("display_name", "").strip() or None
            user.email = request.form.get("email", "").strip() or None
            user.is_active = bool(request.form.get("is_active", True))
            if current_user.id == user.id and request.form.get("is_admin") == "on" and not user.is_admin:
                # 自我降级保护：避免最后一个管理员误操作
                admin_count = User.query.filter_by(is_admin=True).count()
                if admin_count <= 1:
                    flash("至少需要保留一个管理员，无法修改自身管理员状态", "danger")
                    return redirect(url_for("admin.user_edit", user_id=user.id))
            user.is_admin = bool(request.form.get("is_admin"))
            new_password = request.form.get("password", "").strip()
            if new_password:
                user.set_password(new_password)
            db.session.commit()
            flash("用户信息已更新", "success")
            return redirect(url_for("admin.user_edit", user_id=user.id))

        if action == "bind_role":
            role_id = request.form.get("role_id", type=int)
            remark = request.form.get("remark", "").strip()
            if role_id and not UserRole.query.filter_by(user_id=user.id, role_id=role_id).first():
                db.session.add(UserRole(user_id=user.id, role_id=role_id, remark=remark or None))
                db.session.commit()
                flash("已绑定角色", "success")
            else:
                flash("角色不存在或已绑定", "warning")
            return redirect(url_for("admin.user_edit", user_id=user.id) + "#roles")

        if action == "unbind_role":
            binding_id = request.form.get("binding_id", type=int)
            b = UserRole.query.filter_by(id=binding_id, user_id=user.id).first()
            if b:
                db.session.delete(b)
                db.session.commit()
                flash("已解绑角色", "info")
            return redirect(url_for("admin.user_edit", user_id=user.id) + "#roles")

    available_roles = (RamRole.query
                       .filter(~RamRole.id.in_([r.role_id for r in user.roles]))
                       .order_by(RamRole.name).all()) if user.roles else RamRole.query.order_by(RamRole.name).all()
    return render_template("admin/user_form.html", mode="edit",
                           user=user, form=None, available_roles=available_roles)


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
def user_delete(user_id):
    user = User.query.get_or_404(user_id)
    if current_user.id == user.id:
        flash("不能删除当前登录的管理员账号", "danger")
        return redirect(url_for("admin.user_list"))
    admin_count = User.query.filter_by(is_admin=True).count()
    if user.is_admin and admin_count <= 1:
        flash("至少需要保留一个管理员", "danger")
        return redirect(url_for("admin.user_list"))

    username = user.username
    db.session.delete(user)
    db.session.commit()
    flash(f"已删除用户 {username}", "info")
    return redirect(url_for("admin.user_list"))


# ============================================================
# RAM Role 管理
# ============================================================
@admin_bp.route("/roles")
def role_list():
    q = request.args.get("q", "").strip()
    query = RamRole.query
    if q:
        query = query.filter(RamRole.name.like(f"%{q}%") | RamRole.arn.like(f"%{q}%"))
    roles = query.order_by(RamRole.created_at.desc()).all()
    return render_template("admin/roles.html", roles=roles, q=q)


@admin_bp.route("/roles/new", methods=["GET", "POST"])
def role_create():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        arn = request.form.get("arn", "").strip()
        description = request.form.get("description", "").strip()
        is_active = bool(request.form.get("is_active", True))

        if not name or not arn:
            flash("角色名和 ARN 不能为空", "danger")
            return render_template("admin/role_form.html", mode="create",
                                   role=None, form=request.form)
        if RamRole.query.filter_by(name=name).first():
            flash("角色名已存在", "danger")
            return render_template("admin/role_form.html", mode="create",
                                   role=None, form=request.form)
        if RamRole.query.filter_by(arn=arn).first():
            flash("ARN 已存在", "danger")
            return render_template("admin/role_form.html", mode="create",
                                   role=None, form=request.form)

        r = RamRole(name=name, arn=arn, description=description or None,
                    is_active=is_active)
        db.session.add(r)
        db.session.commit()
        flash(f"角色 {name} 创建成功", "success")
        return redirect(url_for("admin.role_edit", role_id=r.id))

    return render_template("admin/role_form.html", mode="create",
                           role=None, form=None)


@admin_bp.route("/roles/<int:role_id>/edit", methods=["GET", "POST"])
def role_edit(role_id):
    role = RamRole.query.get_or_404(role_id)
    if request.method == "POST":
        role.name = request.form.get("name", "").strip()
        role.arn = request.form.get("arn", "").strip()
        role.description = request.form.get("description", "").strip() or None
        role.is_active = bool(request.form.get("is_active", True))
        db.session.commit()
        flash("角色已更新", "success")
        return redirect(url_for("admin.role_edit", role_id=role.id))
    return render_template("admin/role_form.html", mode="edit", role=role, form=None)


@admin_bp.route("/roles/<int:role_id>/delete", methods=["POST"])
def role_delete(role_id):
    role = RamRole.query.get_or_404(role_id)
    name = role.name
    db.session.delete(role)
    db.session.commit()
    flash(f"已删除角色 {name}", "info")
    return redirect(url_for("admin.role_list"))
