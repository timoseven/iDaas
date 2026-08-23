"""SAML IdP 公开端点：metadata"""
from flask import Blueprint, Response, current_app

from . import csrf
from .saml import build_metadata, SamlError

saml_bp = Blueprint("saml", __name__)


@saml_bp.route("/saml/metadata")
@csrf.exempt
def metadata():
    """返回 IdP Metadata XML。

    管理员将本 URL 内容粘贴到阿里云 RAM 控制台的 SAML IdP 创建表单即可。
    本端点公开可访问，不要求登录或 CSRF。
    """
    try:
        xml = build_metadata()
    except SamlError as e:
        return Response(f"IdP metadata 不可用：{e}", status=503,
                        mimetype="text/plain")
    return Response(xml, mimetype="application/xml", headers={
        "Cache-Control": "no-store",
    })
