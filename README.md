# iDaas — 多云 SAML 2.0 IdP（Go 实现）

一个独立的身份认证网站，**自身作为 SAML 2.0 Identity Provider**：本地账号 → 一个或多个云厂商角色。用户登录站点后选择角色，站点用 X.509 私钥签发 SAML Response 并自动 POST 到对应云的 ACS，免密进入控制台。

内置 6 个云预设（阿里云 / 腾讯云 / AWS / 火山引擎 / Azure / Google GCP），各云的 ACS URL、SAML 属性名、Role 属性值拼接顺序均已内置，新建角色时选择云厂商即可。

- 服务端**不需要任何云厂商 AK/SK / AccessKey**，仅持有 IdP 自己的 X.509 私钥用于签名
- 同一角色可被多个本地用户共享；同一用户可绑定多个云的多个角色
- 本地账号 `username/password` 认证，密码 bcrypt 哈希存储
- 协议相同（SAML 2.0 + rsa-sha256 enveloped 双签名），各云差异在 Attribute 与 ACS

## 技术栈
- Go 1.22+（增强型 `net/http` ServeMux 路由，`html/template` + `embed.FS`）
- `go.etcd.io/bbolt` —— 单文件 `.db` 二进制 KV 存储（B+tree，非 SQLite）
- `github.com/crewjam/saml` + `github.com/russellhaering/goxmldsig` —— SAML 2.0 数据类型与 xmldsig 签名
- `golang.org/x/crypto/bcrypt` —— 密码哈希
- 纯原生 HTML/CSS/JS，无前端构建

## 支持的云厂商

| 云 | 标识 | ACS URL | Role 属性值拼接顺序 | 是否需 Provider |
| --- | --- | --- | --- | --- |
| 阿里云 | `aliyun` | `https://signin.aliyun.com/saml/SSO` | `<IdP-ARN>,<Role-ARN>` | 是（IdP ARN） |
| 腾讯云 | `tencent` | `https://cloud.tencent.com/saml/sso` | `<Role-ARN>,<Provider>` | 是（SAML Provider） |
| AWS | `aws` | `https://signin.aws.amazon.com/saml` | `<Role-ARN>,<Principal-ARN>` | 是（Principal / SAML Provider ARN） |
| 火山引擎 | `volc` | `https://signin.volcengine.com/saml/SSO` | `<Provider>,<Role-ARN>` | 是（Trusted Principal） |
| Azure | `azure` | `https://login.microsoftonline.com/<tenant>/saml2` | 无 Role 属性（NameID 登录） | 否 |
| Google GCP | `gcp` | `https://www.googleapis.com/cloud-identity/saml/acs` | 无 Role 属性（Workforce Pool） | 否 |

> Azure/GCP 仅以 NameID 作为联合身份，应用侧 / Workforce Pool 决定权限，无需 Role 扮演属性；在 iDaas 角色表单中 Provider ARN 留空即可。

规格定义见 [internal/saml/clouds.go](internal/saml/clouds.go)，新增云只需在 `clouds` 注册表加一项。

## 架构
```
   alice ──┐
   bob    ─┤  1. 登录 iDaas /login（本地账号）
           ▼
       [iDaas IdP:8088]   2. 选角色 → BuildResponse(username, Role{Cloud,ARN,ProviderARN})
           │                 ├─ 按 role.Cloud 派发 ACS / 属性名 / Role 值顺序
           │                 ├─ Assertion + Response 各做一次 enveloped rsa-sha256 签名
           │ 3. base64(SAMLResponse) 自动 POST
           ▼
       对应云 ACS（如 AWS https://signin.aws.amazon.com/saml）
           │
           ▼
       云控制台（以对应角色身份）
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
│   ├── saml/
│   │   ├── clouds.go          # 6 云规格预设（ACS / 属性名 / 拼接顺序）
│   │   └── idp.go             # SAML IdP：metadata + BuildResponse 派发签名
│   └── webserver/             # HTTP 层（路由/模板/静态/flash）
│       ├── server.go          # 路由注册 + 模板加载 + render + cloudLabel FuncMap
│       ├── auth_routes.go     # /login /logout
│       ├── portal.go          # / /role/{id}/console /saml/metadata（按云分组）
│       ├── admin.go           # /admin/* 用户/角色/绑定 CRUD（含 cloud / provider_arn）
│       └── web/               # embed 资源：templates/ + static/css/
├── certs/idp.crt, idp.key     # IdP 证书私钥（手动放置）
├── docs/aliyun-setup.md       # 阿里云侧配置检查清单（其他云可类比）
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
config 从**进程环境变量**读取，支持用 `-env` 加载 .env 文件：
```bash
cp .env.example .env
# 编辑 .env，至少设置 SECRET_KEY
./idaas -env .env
```
> 已存在的进程环境变量优先，不会被 .env 文件覆盖。也可继续用 `set -a; . ./.env; set +a` 或 systemd `EnvironmentFile=.env`。
关键变量：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `LISTEN_ADDR` | `:8088` | 监听地址 |
| `DB_PATH` | `idaas.db` | bbolt 数据库路径 |
| `SECRET_KEY` | dev 值 | 会话相关；生产必须改为强随机 |
| `SAML_ENTITY_ID` | `http://localhost:8088/saml/metadata` | IdP EntityID |
| `SAML_BASE_URL` | `http://localhost:8088` | 站点对外 base URL |
| `SAML_CERT_PATH` / `SAML_KEY_PATH` | `certs/idp.crt` / `certs/idp.key` | IdP 证书/私钥 |
| `SAML_ASSERTION_VALID_MINUTES` | `5` | Assertion 有效期 |

> 各云的 ACS URL 与 SAML 属性规格内置在代码中（见上表），无需在环境变量配置；IdP/Provider/Principal ARN 按角色在后台表单填写。

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

## 云侧配置（每个云一次性）
通用步骤（以阿里云为例，详见 [docs/aliyun-setup.md](docs/aliyun-setup.md)；其他云类比）：
1. 访问 `/saml/metadata` 取 IdP metadata XML
2. 在云控制台创建/登记 SAML IdP（上传 metadata）→ 记录 **IdP/Provider/Principal ARN**（Azure/GCP 无此项）
3. 在云控制台创建扮演角色 / 联合应用 → 记录 **角色 ARN**（Azure 为应用 Entity ID，GCP 为 Workforce Pool Provider ID）
4. iDaas 后台 → 角色管理 → 新建角色：选择**云厂商**，填入角色 ARN 与 Provider ARN → 用户管理绑定用户

## 用户使用流程
1. 普通用户 `/login` 输入用户名密码
2. 门户 `/` 按**云分组**列出已绑定角色
3. 点击「登录控制台」→ 浏览器自动 POST `SAMLResponse` 到对应云 ACS
4. 云校验签名、扮演角色，进入控制台

## SAML Response 关键字段（按云派发）
- `Issuer` = IdP EntityID
- `NameID` = 网站用户名
- `Destination` = 对应云 ACS URL
- Role 属性（阿里云 / 腾讯云 / AWS / 火山引擎）：属性名与值拼接顺序见上表（如 AWS 为 `<Role-ARN>,<Principal-ARN>`，与阿里云顺序相反）
- Azure / GCP：仅 NameID，无 Role 属性
- Response 与 Assertion 各一次 enveloped xmldsig 签名（rsa-sha256 + sha256）

## CLI
```bash
./idaas                        # 启动 HTTP 服务
./idaas -env .env              # 启动并加载指定 env 文件（已存在的环境变量优先）
./idaas createsuperuser [...]  # 创建管理员（支持 -username/-password/-email/-display-name/-db）
```

## 安全说明
- 服务端不存任何云厂商 AK/SK / AccessKey，认证完全依赖 SAML 签名
- 密码 bcrypt 哈希；会话存于 bbolt，cookie 仅持随机 session_id（HttpOnly）
- 所有写请求启用 CSRF（双提交 cookie 模式）
- `/saml/metadata` 公开只读；私钥不会出现在 metadata 中
- 最后一个管理员账户无法被删除或降级；不能删除当前登录的管理员
- Assertion 默认 5 分钟有效期，过期后云拒绝重放
