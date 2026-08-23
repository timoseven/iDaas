# iDaas — SAML 2.0 IdP + 阿里云 RAM 角色 SSO（Go 实现）

一个独立的身份认证网站，**自身作为 SAML 2.0 Identity Provider**：多个本地账号 → 一个或多个阿里云 RAM 角色。用户登录网站后选择角色，站点用 X.509 私钥签发 SAML Response 并自动 POST 到阿里云 ACS，免密进入控制台。

- 服务端**不需要任何阿里云 AK/SK**，仅持有 IdP 自己的 X.509 私钥用于签名
- 同一 RAM 角色可被多个本地用户共享；同一用户也可绑定多个角色
- 本地账号 `username/password` 认证，密码 bcrypt 哈希存储

## 技术栈
- Go 1.22+（增强型 `net/http` ServeMux 路由，`html/template` + `embed.FS`）
- `go.etcd.io/bbolt` —— 单文件 `.db` 二进制 KV 存储（B+tree，非 SQLite）
- `github.com/crewjam/saml` + `github.com/russellhaering/goxmldsig` —— SAML 2.0 数据类型与 xmldsig 签名
- `golang.org/x/crypto/bcrypt` —— 密码哈希
- 纯原生 HTML/CSS/JS，无前端构建

## 架构
```
   alice ──┐
   bob    ─┤  1. 登录 iDaas /login（本地账号）
           ▼
       [iDaas IdP:8088]   2. 选角色 → BuildResponse(username, roleARN)
           │                 ├─ Assertion + Response 各做一次 enveloped rsa-sha256 签名
           │ 3. base64(SAMLResponse) 自动 POST
           ▼
       阿里云 ACS  https://signin.aliyun.com/saml/SSO
           │
           ▼
       阿里云控制台（以 RAM 角色身份）
```
存储：`idaas.db`（bbolt）。证书：`certs/idp.crt` + `certs/idp.key`。

## 目录结构
```
iDaas/
├── cmd/idaas/main.go          # 启动入口 + createsuperuser 子命令
├── internal/
│   ├── config/config.go       # 环境变量加载
│   ├── models/models.go       # User / RamRole / UserRole / BindingView
│   ├── store/store.go         # bbolt 存储层（用户/角色/绑定/会话 CRUD）
│   ├── auth/auth.go           # 会话 + CSRF（双提交 cookie）+ bcrypt + 权限中间件
│   ├── saml/idp.go            # SAML IdP：metadata 生成 + BuildResponse 签名
│   └── webserver/             # HTTP 层（路由/模板/静态/flash）
│       ├── server.go          # 路由注册 + 模板加载 + render
│       ├── auth_routes.go     # /login /logout
│       ├── portal.go          # / /role/{id}/console /saml/metadata
│       ├── admin.go           # /admin/* 用户/角色/绑定 CRUD
│       └── web/               # embed 资源：templates/ + static/css/
├── certs/idp.crt, idp.key     # IdP 证书私钥（手动放置）
├── docs/aliyun-setup.md       # 阿里云侧配置检查清单
├── .env.example
├── go.mod / go.sum
└── README.md
```

## 快速开始

### 1. 构建
```bash
go build -o idaas ./cmd/idaas
```

### 2. 生成 IdP 证书（仅一次）
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 \
  -keyout certs/idp.key -out certs/idp.crt \
  -days 3650 -nodes -subj "/CN=iDaas IdP"
chmod 600 certs/idp.key
```

### 3. 配置环境变量
config 从**进程环境变量**读取（不会自动解析 `.env` 文件）。推荐：
```bash
cp .env.example .env
# 编辑 .env，至少设置 SECRET_KEY 与 SAML_IDP_ARN
set -a; . ./.env; set +a
```
关键变量：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8088` | 监听地址 |
| `DB_PATH` | `idaas.db` | bbolt 数据库路径 |
| `SECRET_KEY` | dev 值 | 会话相关；生产必须改为强随机 |
| `SAML_ENTITY_ID` | `http://localhost:8088/saml/metadata` | IdP EntityID |
| `SAML_BASE_URL` | `http://localhost:8088` | 站点对外 base URL |
| `SAML_ACS_URL` | `https://signin.aliyun.com/saml/SSO` | 阿里云 ACS，勿改 |
| `SAML_CERT_PATH` / `SAML_KEY_PATH` | `certs/idp.crt` / `certs/idp.key` | IdP 证书/私钥 |
| `SAML_IDP_ARN` | 空 | 阿里云侧创建 IdP 后回填，详见 [docs/aliyun-setup.md](docs/aliyun-setup.md) |
| `SAML_ASSERTION_VALID_MINUTES` | `5` | Assertion 有效期 |

### 4. 创建管理员
```bash
./idaas createsuperuser -username admin -password <pwd> -email a@b.com -display-name Admin
# 或交互式输入：./idaas createsuperuser
```

### 5. 启动
```bash
./idaas    # http://localhost:8088/login
```
生产部署建议置于 HTTPS 反向代理之后，并用 systemd 管理进程（`EnvironmentFile=.env`）。

## 阿里云侧配置（一次性）
见 [docs/aliyun-setup.md](docs/aliyun-setup.md) 检查清单。要点：
1. 访问 `/saml/metadata` 取 IdP metadata XML
2. 阿里云 RAM → SSO → 创建 IdP（上传 metadata）→ 记录 **IdP ARN**
3. 回填 `SAML_IDP_ARN` 并重启
4. RAM → 创建角色（受信实体=身份提供商）→ 记录 **角色 ARN** → 附加权限策略
5. iDaas 后台 → RAM 角色管理登记角色 → 用户管理绑定用户

## 用户使用流程
1. 普通用户 `/login` 输入用户名密码
2. 门户 `/` 列出已绑定角色
3. 点击「登录控制台」→ 浏览器自动 POST `SAMLResponse` 到阿里云 ACS
4. 阿里云校验签名、扮演 RAM 角色，进入控制台

## SAML Response 关键字段
- `Issuer` = IdP EntityID
- `NameID` = 网站用户名
- `Attribute: https://www.aliyun.com/SAML-Role/Attributes/Role` = `<IdP-ARN>,<Role-ARN>`
- `Attribute: https://www.aliyun.com/SAML-Role/Attributes/RoleSessionName` = 用户名
- Response 与 Assertion 各一次 enveloped xmldsig 签名（rsa-sha256 + sha256）

## CLI
```bash
./idaas                       # 启动 HTTP 服务
./idaas createsuperuser [...]  # 创建管理员（支持 -username/-password/-email/-display-name/-db）
```

## 安全说明
- 服务端不存任何阿里云 AK/SK，认证完全依赖 SAML 签名
- 密码 bcrypt 哈希；会话存于 bbolt，cookie 仅持随机 session_id（HttpOnly）
- 所有写请求启用 CSRF（双提交 cookie 模式）
- `/saml/metadata` 公开只读；私钥不会出现在 metadata 中
- 最后一个管理员账户无法被删除或降级；不能删除当前登录的管理员
- Assertion 默认 5 分钟有效期，过期后阿里云拒绝重放
