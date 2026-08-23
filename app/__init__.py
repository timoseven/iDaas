"""Flask 应用工厂"""
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, AnonymousUserMixin
from flask_wtf import CSRFProtect

from .config import Config

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

login_manager.login_view = "auth.login"
login_manager.login_message = "请先登录"
login_manager.login_message_category = "warning"


class AnonymousUser(AnonymousUserMixin):
    """未登录访客对象，统一提供 is_admin / is_active 等字段，避免模板与权限检查 KeyError"""

    is_admin = False
    is_active = False
    username = ""
    display_name = None
    email = None
    roles = []

    @property
    def id(self):
        return None


login_manager.anonymous_user = AnonymousUser


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # 测试模式关闭 CSRF，便于自动化测试
    if app.config.get("TESTING"):
        app.config["WTF_CSRF_ENABLED"] = False

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    from .auth import auth_bp
    from .user_portal import portal_bp
    from .admin import admin_bp
    from .saml_routes import saml_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(portal_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(saml_bp)

    with app.app_context():
        from . import models  # noqa: F401  注册模型
        db.create_all()

    return app
