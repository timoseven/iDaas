# iDaas - SAML 2.0 IdP + 阿里云 RAM 角色 SSO

一个独立的身份认证网站，**自身作为 SAML 2.0 Identity Provider**：多个本地账号 → 一个或多个阿里云 RAM 角色。用户登录网站后选择角色，站点签发已签名的 SAML Response 并自动 POST 到阿里云 ACS，免密进入控制台。

## 架构

```
                              ┌── 阿里云控制台
                              │   (role: prod-readonly)
   alice ──┐                  │
   bob    ─┤  HTTPS SAML POST │
           ▼                  ▼
       [iDaas IdP] ──sign──> 阿里云 ACS (https://signin.aliyun.com/saml/SSO)
           │
           │ X.509 私钥 (certs/idp.key)
           │
       [SQLite：本地账号 + 角色 ARN 绑定]
```

- **同一 RAM 角色**可被多个本地用户共享；同一用户也可绑定多个角色，登录时自行选择
- 站点用本地 `username/password` 认证，**完全不接触**用户的阿里云账号密码
- 服务端**不需要任何阿里云 AK/SK**，仅持有 IdP 自己的 X.509 私钥用于签名

## 技术栈

- Python 3.8+ / Flask 3 / SQLAlchemy / Flask-Login / Flask-WTF
- `lxml` + `signxml` 用于构造和签名 SAML XML
- SQLite（开箱即用，可换 PostgreSQL/MySQL）
- 原生 HTML/CSS/JS 前端，无前端构建依赖

## 目录结构

```
iDaas/
├── app/
│   ├── __init__.py        # 应用工厂
│   ├── config.py          # 环境变量加载（SAML_* 项）
│   ├── models.py          # User / RamRole / UserRole
│   ├── saml.py            # build_saml_response() + build_metadata() + load_idp_credentials()
│   ├── saml_routes.py     # /saml/metadata 公开端点
│   ├── auth.py            # /login /logout
│   ├── user_portal.py     # / + /role/<id>/console (选角色 → POST SAMLResponse 到 ACS)
│   ├── admin.py           # /admin/* 用户/角色 CRUD + 绑定管理
│   ├── templates/         # base / login / portal/* / admin/*
│   └── static/css/style.css
├── certs/                 # IdP 证书私钥（管理员手动放置）
│   ├── idp.crt
│   └── idp.key
├── manage.py              # CLI: initdb / createsuperuser / list-users / list-roles
├── run.py                 # 启动入口（端口 8088）
├── requirements.txt
├── .env.example
└── instance/idaas.db      # 首次启动自动创建
```

## 快速开始

### 1. 安装依赖

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. 生成 IdP 证书（管理员手动）

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 \
  -keyout certs/idp.key -out certs/idp.crt \
  -days 3650 -nodes -subj "/CN=iDaas IdP"
chmod 600 certs/idp.key
```

证书只需生成一次，长期使用；私钥必须保密（已加入 `.gitignore`）。

### 3. 配置环境变量

```bash
cp .env.example .env
# 编辑 .env，至少填入 SECRET_KEY
```

关键变量：

| 变量 | 说明 |
| --- | --- |
| `SECRET_KEY` | Flask 会话签名密钥，生产必须改 |
| `SAML_ENTITY_ID` | IdP EntityID，建议即 metadata URL |
| `SAML_BASE_URL` | 站点对外 base URL（用于 metadata 中的 SSO endpoint Location） |
| `SAML_ACS_URL` | 阿里云固定 ACS，默认 `https://signin.aliyun.com/saml/SSO`，无需改 |
| `SAML_CERT_PATH` / `SAML_KEY_PATH` | IdP 证书与私钥路径 |
| `SAML_IDP_ARN` | 阿里云侧创建 SAML IdP 后回填：`acs:ram::<主账号ID>:saml-provider/<IdP名>` |
| `SAML_ASSERTION_VALID_MINUTES` | SAML Assertion 有效期（分钟），默认 5 |

### 4. 初始化数据库 + 创建管理员

```bash
python3 manage.py initdb
python3 manage.py createsuperuser
# 交互输入用户名/密码/邮箱；或非交互：
python3 manage.py createsuperuser --username admin --password <pwd> --email a@b.com
```

### 5. 启动服务

```bash
python3 run.py    # http://localhost:8088/login
```

生产部署建议用 gunicorn：

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8088 run:app
```

## 阿里云侧配置（一次性）

1. 启动 iDaas 后访问 `https://your-domain/saml/metadata` 拿到 IdP metadata XML
2. 阿里云 RAM 控制台 → **SSO 管理** → **SAML** → **角色 SSO** → **创建 IdP**
   - 上传 metadata 文件（或粘贴 URL）
   - 记录生成的 **IdP ARN**：`acs:ram::<主账号ID>:saml-provider/idaas`
3. RAM 控制台 → **角色** → **创建角色** → 受信实体选 **身份提供商**
   - 选择上面创建的 IdP，完成角色创建
   - 复制 **角色 ARN**：`acs:ram::<主账号ID>:role/<role-name>`
   - 给角色附加合适的权限策略（AliyunRAMFullAccess / OSS ReadOnly 等）
4. 将 IdP ARN 回填到 iDaas 的 `.env` 中 `SAML_IDP_ARN`
5. 重启 iDaas，在管理后台 → RAM 角色管理 → 添加角色，把上面角色 ARN 录入
6. 用户管理 → 新建本地用户 → 编辑用户 → 绑定刚创建的角色

## 用户使用流程

1. 普通用户访问 `/login`，输入用户名密码登录
2. 门户首页 `/` 列出其绑定的 RAM 角色卡片
3. 点击「进入阿里云控制台」→ 浏览器自动 POST SAMLResponse 到阿里云 ACS
4. 阿里云校验签名、扮演对应 RAM 角色，重定向到控制台首页
5. 用户在控制台的所有操作都以该 RAM 角色身份进行

## SAML Response 关键字段

- `Issuer` = IdP EntityID
- `NameID` = 网站用户名（即阿里云会话标识）
- `Attribute: https://www.aliyun.com/SAML-Role/Attributes/Role` = `<IdP-ARN>,<Role-ARN>`
- `Attribute: https://www.aliyun.com/SAML-Role/Attributes/RoleSessionName` = 用户名
- 用 X.509 私钥对 Response 与 Assertion 各做一次 enveloped xmldsig 签名（rsa-sha256 + sha256）

## CLI 命令

```bash
python3 manage.py initdb              # 初始化数据库表
python3 manage.py createsuperuser    # 创建管理员
python3 manage.py changepassword <u> # 改某用户密码
python3 manage.py list-users         # 列出用户
python3 manage.py list-roles         # 列出 RAM 角色
```

## 安全说明

- 服务端不存储任何阿里云 AK/SK，认证完全依赖 SAML 签名
- SAML Assertion 默认 5 分钟有效期，过期后阿里云会拒绝重放
- `/saml/metadata` 是公开只读端点，可被阿里云拉取；私钥不会出现在 metadata 中
- 所有 POST 表单启用 CSRF；测试模式 `TESTING=True` 会自动关闭
- 用户管理面板支持停用账号、解绑角色；最后一个管理员账号无法被删除或降级
