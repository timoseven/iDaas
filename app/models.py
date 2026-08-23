"""数据模型

关系说明：
    User 1 -- * UserRole * -- 1 RamRole

    一个网站用户可绑定多个阿里云 RAM Role，一个 Role 也可被多个用户使用。
    用户登录后从自己绑定的 Role 列表中选择一个，再去申请 STS 临时凭证。
"""
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from . import db, login_manager


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    display_name = db.Column(db.String(128))
    email = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    roles = db.relationship("UserRole", back_populates="user", cascade="all, delete-orphan")

    def set_password(self, raw):
        # 使用 pbkdf2 避免依赖 OpenSSL scrypt（macOS 系统 Python 默认 LibreSSL 无 scrypt）
        self.password_hash = generate_password_hash(raw, method="pbkdf2:sha256", salt_length=16)

    def check_password(self, raw):
        return check_password_hash(self.password_hash, raw)

    def __repr__(self):
        return f"<User {self.username}>"


class RamRole(db.Model):
    __tablename__ = "ram_roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    # acs:ram::<主账号ID>:role/<角色名> —— 阿里云 RAM 角色的 ARN
    arn = db.Column(db.String(255), unique=True, nullable=False)
    description = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    users = db.relationship("UserRole", back_populates="role", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<RamRole {self.name}>"


class UserRole(db.Model):
    __tablename__ = "user_roles"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey("ram_roles.id"), nullable=False, index=True)
    remark = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (db.UniqueConstraint("user_id", "role_id", name="uq_user_role"),)

    user = db.relationship("User", back_populates="roles")
    role = db.relationship("RamRole", back_populates="users")


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
