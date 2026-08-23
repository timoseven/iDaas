"""应用配置"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-insecure-key-change-me")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///idaas.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ----- SAML 2.0 IdP 配置 -----
    # IdP 的 EntityID（通常就是 metadata URL）
    SAML_ENTITY_ID = os.getenv("SAML_ENTITY_ID", "http://localhost:8088/saml/metadata")

    # 站点对外可访问的 base URL（用于生成 metadata 中的 Location）
    SAML_BASE_URL = os.getenv("SAML_BASE_URL", "http://localhost:8088").rstrip("/")

    # 阿里云 SAML ACS（阿里云固定的 ACS 地址）
    SAML_ACS_URL = os.getenv("SAML_ACS_URL", "https://signin.aliyun.com/saml/SSO")

    # 管理员手动提供的 X.509 证书与私钥路径
    SAML_CERT_PATH = os.getenv("SAML_CERT_PATH", "certs/idp.crt")
    SAML_KEY_PATH = os.getenv("SAML_KEY_PATH", "certs/idp.key")

    # 阿里云侧创建的 SAML IdP ARN：acs:ram::<主账号ID>:saml-provider/<IdP名>
    # 在 RamRole.arn 中保存的是 Role ARN；本字段是 IdP ARN，二者拼到 SAML Attribute 中
    SAML_IDP_ARN = os.getenv("SAML_IDP_ARN", "")

    # SAML 时间窗口
    SAML_ASSERTION_VALID_MINUTES = int(os.getenv("SAML_ASSERTION_VALID_MINUTES", "5"))

    # 组织信息（写入 metadata）
    SAML_ORG_NAME = os.getenv("SAML_ORG_NAME", "iDaas")
    SAML_ORG_DISPLAY_NAME = os.getenv("SAML_ORG_DISPLAY_NAME", "iDaas Identity Provider")
    SAML_ORG_URL = os.getenv("SAML_ORG_URL", "")
    SAML_CONTACT_EMAIL = os.getenv("SAML_CONTACT_EMAIL", "")

    # 会话有效期（小时） - 网站登录态
    PERMANENT_SESSION_LIFETIME = 3600 * 8
