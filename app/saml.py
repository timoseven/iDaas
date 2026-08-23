"""SAML 2.0 IdP 实现：证书加载、SAMLResponse 构造与签名、IdP metadata 生成

文档：
    https://docs.oasis.org/security/saml/v2.0/saml-core-2.0-os.pdf
    https://www.alibabacloud.com/help/ram/user-guide/roles-for-saml-based-federation
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Tuple

from lxml import etree
from signxml import XMLSigner, methods

from flask import current_app


# SAML 常量
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_XMLDSIG = "http://www.w3.org/2000/09/xmldsig#"
NS_METADATA = "urn:oasis:names:tc:SAML:2.0:metadata"

# 阿里云约定的 SAML 属性名
ATTR_ROLE = "https://www.aliyun.com/SAML-Role/Attributes/Role"
ATTR_SESSION_NAME = "https://www.aliyun.com/SAML-Role/Attributes/RoleSessionName"
ATTR_SESSION_DURATION = "https://www.aliyun.com/SAML-Role/Attributes/SessionDuration"

NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


class SamlError(Exception):
    """SAML IdP 操作异常"""


# ------------------------------------------------------------
# 证书 / 私钥加载
# ------------------------------------------------------------
def load_idp_credentials() -> Tuple[str, str]:
    """返回 (cert_pem, key_pem)。

    路径来自 SAML_CERT_PATH / SAML_KEY_PATH，由管理员手动提供。
    """
    cert_path = current_app.config["SAML_CERT_PATH"]
    key_path = current_app.config["SAML_KEY_PATH"]
    if not cert_path or not key_path:
        raise SamlError("未配置 SAML_CERT_PATH / SAML_KEY_PATH")

    if not os.path.isfile(cert_path):
        raise SamlError(f"证书文件不存在：{cert_path}（请用 openssl 生成后填入 .env）")
    if not os.path.isfile(key_path):
        raise SamlError(f"私钥文件不存在：{key_path}")

    with open(cert_path, "r", encoding="utf-8") as f:
        cert_pem = f.read().strip()
    with open(key_path, "r", encoding="utf-8") as f:
        key_pem = f.read().strip()

    if "BEGIN CERTIFICATE" not in cert_pem:
        raise SamlError(f"{cert_path} 不是合法的 PEM 证书")
    if "PRIVATE KEY" not in key_pem:
        raise SamlError(f"{key_path} 不是合法的 PEM 私钥")
    return cert_pem, key_pem


def get_cert_b64() -> str:
    """从 PEM 证书中提取 DER base64 字符串，供 metadata 使用"""
    cert_pem, _ = load_idp_credentials()
    lines = [ln.strip() for ln in cert_pem.splitlines()
             if ln.strip() and not ln.startswith("-----")]
    return "".join(lines)


# ------------------------------------------------------------
# SAML Response 构造
# ------------------------------------------------------------
def _q(ns: str, tag: str) -> str:
    return f"{{{ns}}}{tag}"


def _fmt_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_saml_response(
    username: str,
    role_arn: str,
    idp_arn: str | None = None,
    session_duration: int | None = None,
    recipient: str | None = None,
) -> str:
    """构造并签名 SAML Response XML，返回字符串。

    Args:
        username: 网站用户名（用于 NameID 与 RoleSessionName）
        role_arn: 用户选择扮演的阿里云 RAM Role ARN
        idp_arn: 阿里云侧 IdP ARN；为空时取自 SAML_IDP_ARN
        session_duration: 临时凭证有效期（秒），可选
        recipient: ACS URL，为空时取自 SAML_ACS_URL

    Returns:
        已签名的 SAML Response XML 字符串
    """
    cert_pem, key_pem = load_idp_credentials()
    entity_id = current_app.config["SAML_ENTITY_ID"]
    acs_url = recipient or current_app.config["SAML_ACS_URL"]
    idp_arn = idp_arn or current_app.config["SAML_IDP_ARN"]
    if not idp_arn:
        raise SamlError("未配置 SAML_IDP_ARN（阿里云侧创建 SAML IdP 后填入）")

    now = datetime.now(timezone.utc)
    valid_minutes = current_app.config["SAML_ASSERTION_VALID_MINUTES"]
    issue_instant = _fmt_time(now)
    not_before = _fmt_time(now - timedelta(minutes=1))
    not_on_or_after = _fmt_time(now + timedelta(minutes=valid_minutes))

    response_id = "_" + uuid.uuid4().hex
    assertion_id = "_" + uuid.uuid4().hex

    # ---------- 构建 Assertion ----------
    assertion = etree.Element(
        _q(NS_SAML, "Assertion"),
        ID=assertion_id, Version="2.0", IssueInstant=issue_instant,
        nsmap={"saml": NS_SAML},
    )
    iss = etree.SubElement(assertion, _q(NS_SAML, "Issuer"))
    iss.text = entity_id

    subject = etree.SubElement(assertion, _q(NS_SAML, "Subject"))
    nameid = etree.SubElement(
        subject, _q(NS_SAML, "NameID"),
        Format=NAMEID_UNSPECIFIED,
    )
    nameid.text = username
    sc = etree.SubElement(
        subject, _q(NS_SAML, "SubjectConfirmation"),
        Method=CM_BEARER,
    )
    etree.SubElement(
        sc, _q(NS_SAML, "SubjectConfirmationData"),
        NotOnOrAfter=not_on_or_after, Recipient=acs_url,
    )

    etree.SubElement(
        assertion, _q(NS_SAML, "Conditions"),
        NotBefore=not_before, NotOnOrAfter=not_on_or_after,
    )

    authn_stmt = etree.SubElement(
        assertion, _q(NS_SAML, "AuthnStatement"),
        AuthnInstant=issue_instant, SessionIndex=assertion_id,
        SessionNotOnOrAfter=not_on_or_after,
    )
    authn_ctx = etree.SubElement(
        authn_stmt, _q(NS_SAML, "AuthnContext"),
    )
    class_ref = etree.SubElement(
        authn_ctx, _q(NS_SAML, "AuthnContextClassRef"),
    )
    class_ref.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    attr_stmt = etree.SubElement(assertion, _q(NS_SAML, "AttributeStatement"))

    # Role 属性：阿里云期望值为 "<IdP-ARN>,<Role-ARN>"
    role_attr = etree.SubElement(
        attr_stmt, _q(NS_SAML, "Attribute"),
        Name=ATTR_ROLE,
    )
    role_val = etree.SubElement(role_attr, _q(NS_SAML, "AttributeValue"))
    role_val.text = f"{idp_arn},{role_arn}"

    # RoleSessionName 属性
    session_attr = etree.SubElement(
        attr_stmt, _q(NS_SAML, "Attribute"),
        Name=ATTR_SESSION_NAME,
    )
    session_val = etree.SubElement(session_attr, _q(NS_SAML, "AttributeValue"))
    session_val.text = username

    # 可选 SessionDuration
    if session_duration:
        dur_attr = etree.SubElement(
            attr_stmt, _q(NS_SAML, "Attribute"),
            Name=ATTR_SESSION_DURATION,
        )
        dur_val = etree.SubElement(dur_attr, _q(NS_SAML, "AttributeValue"))
        dur_val.text = str(session_duration)

    # ---------- 签名 Assertion ----------
    signer = XMLSigner(method=methods.enveloped,
                       signature_algorithm="rsa-sha256",
                       digest_algorithm="sha256")
    # signature 插在 Issuer 之后
    signed_assertion = signer.sign(
        assertion, key=key_pem, cert=cert_pem, reference_uri=assertion_id,
    )

    # ---------- 构建 Response ----------
    response = etree.Element(
        _q(NS_SAMLP, "Response"),
        ID=response_id, Version="2.0", IssueInstant=issue_instant,
        nsmap={"samlp": NS_SAMLP, "saml": NS_SAML, "ds": NS_XMLDSIG},
    )
    resp_iss = etree.SubElement(response, _q(NS_SAML, "Issuer"))
    resp_iss.text = entity_id

    status = etree.SubElement(response, _q(NS_SAMLP, "Status"))
    etree.SubElement(
        status, _q(NS_SAMLP, "StatusCode"),
        Value=STATUS_SUCCESS,
    )

    # 将签名后的 Assertion 追加进 Response
    response.append(signed_assertion)

    # ---------- 签名 Response ----------
    signed_response = signer.sign(
        response, key=key_pem, cert=cert_pem, reference_uri=response_id,
    )

    return etree.tostring(
        signed_response, xml_declaration=True, encoding="UTF-8",
    ).decode("utf-8")


# ------------------------------------------------------------
# IdP Metadata
# ------------------------------------------------------------
def build_metadata() -> str:
    """生成 IdP Metadata XML 字符串（供阿里云上传）"""
    cfg = current_app.config
    entity_id = cfg["SAML_ENTITY_ID"]
    base_url = cfg["SAML_BASE_URL"]
    sso_url = f"{base_url}/saml/sso"

    cert_b64 = get_cert_b64()

    root = etree.Element(
        _q(NS_METADATA, "EntityDescriptor"),
        entityID=entity_id,
        nsmap={"md": NS_METADATA, "ds": NS_XMLDSIG},
    )

    org = etree.SubElement(root, _q(NS_METADATA, "Organization"))
    name = etree.SubElement(org, _q(NS_METADATA, "OrganizationName"))
    name.text = cfg["SAML_ORG_NAME"]
    disp = etree.SubElement(org, _q(NS_METADATA, "OrganizationDisplayName"))
    disp.text = cfg["SAML_ORG_DISPLAY_NAME"]
    url = etree.SubElement(org, _q(NS_METADATA, "OrganizationURL"))
    url.text = cfg["SAML_ORG_URL"] or base_url

    contact = etree.SubElement(
        root, _q(NS_METADATA, "ContactPerson"),
        contactType="technical",
    )
    cemail = etree.SubElement(contact, _q(NS_METADATA, "EmailAddress"))
    cemail.text = cfg["SAML_CONTACT_EMAIL"] or "noreply@example.com"

    idp_desc = etree.SubElement(
        root, _q(NS_METADATA, "IDPSSODescriptor"),
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol",
    )

    key_desc = etree.SubElement(
        idp_desc, _q(NS_METADATA, "KeyDescriptor"),
        use="signing",
    )
    key_info = etree.SubElement(key_desc, _q(NS_XMLDSIG, "KeyInfo"))
    x509_data = etree.SubElement(key_info, _q(NS_XMLDSIG, "X509Data"))
    x509_cert = etree.SubElement(x509_data, _q(NS_XMLDSIG, "X509Certificate"))
    x509_cert.text = cert_b64

    name_id_fmt = etree.SubElement(idp_desc, _q(NS_METADATA, "NameIDFormat"))
    name_id_fmt.text = NAMEID_UNSPECIFIED

    etree.SubElement(
        idp_desc, _q(NS_METADATA, "SingleSignOnService"),
        Binding=BINDING_POST, Location=sso_url,
    )
    etree.SubElement(
        idp_desc, _q(NS_METADATA, "SingleSignOnService"),
        Binding=BINDING_REDIRECT, Location=sso_url,
    )

    return etree.tostring(
        root, xml_declaration=True, encoding="UTF-8", pretty_print=True,
    ).decode("utf-8")
