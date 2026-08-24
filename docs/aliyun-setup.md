# 阿里云侧 SAML IdP 与 RAM 角色配置检查清单

> 一次性配置。完成后将 **IdP ARN** 在 iDaas 后台新建阿里云角色时填入「Provider ARN」字段，将 **角色 ARN** 填入「角色标识 (ARN)」字段。

## 前置：iDaas 已可访问
- [ ] iDaas 服务已启动并可对外访问（生产环境需 HTTPS）
- [ ] 浏览器访问 `https://<your-domain>/saml/metadata` 返回 XML（含 `IDPSSODescriptor` 与 `X509Certificate`）
- [ ] 保存该 metadata XML 内容备用（或记下该 URL 供阿里云拉取）

## 一、创建 SAML IdP（获取 IdP ARN）
- [ ] 登录阿里云主账号控制台
- [ ] 进入 RAM 控制台 → **SSO 管理** → **SAML** → **角色 SSO**
- [ ] 点击 **创建 IdP**
  - [ ] 名称：例如 `idaas`
  - [ ] 元数据上传方式：**上传文件**（或填 metadata URL 让阿里云拉取）
  - [ ] 上传上一步保存的 metadata XML
- [ ] 创建完成后，记录 **IdP ARN**，形如：
      `acs:ram::<主账号ID>:saml-provider/idaas`
- [ ] 将该 IdP ARN 在 iDaas 后台新建阿里云角色时填入「Provider ARN」字段（无需重启）

## 二、创建 RAM 角色（获取 Role ARN）
- [ ] RAM 控制台 → **角色** → **创建角色**
- [ ] 受信实体类型选择 **身份提供商**
- [ ] 选择上一步创建的 IdP（`idaas`）
- [ ] 角色名自定义，例如 `saml-console-admin`
- [ ] 完成创建，记录 **角色 ARN**，形如：
      `acs:ram::<主账号ID>:role/saml-console-admin`
- [ ] 给该角色附加权限策略（按需）：
  - [ ] 例如 `AliyunOSSReadOnlyAccess`、`AliyunRAMFullAccess`（慎用）
  - [ ] 或自定义最小权限策略

## 三、在 iDaas 后台登记角色并绑定用户
- [ ] 管理员登录 iDaas → **角色管理** → **新建角色**
  - [ ] 云厂商：选择「阿里云」
  - [ ] 角色标识 (ARN)：粘贴上一步的角色 ARN
  - [ ] Provider ARN：粘贴第一步的 IdP ARN
  - [ ] 启用：勾选
- [ ] **用户管理** → 新建或编辑用户
  - [ ] 在「角色绑定」区域选择上一步登记的角色并绑定
  - [ ] 保存

## 四、验证
- [ ] 用普通用户登录 iDaas `/login`
- [ ] 门户首页 `/` 看到已绑定的角色卡片
- [ ] 点击「登录控制台」→ 自动跳转到阿里云并进入控制台
- [ ] 控制台右上角身份显示为对应 RAM 角色
- [ ] 若失败：检查角色表单 Provider ARN（IdP ARN）是否已填、角色是否启用、用户是否绑定、iDaas 系统时间是否准确（Assertion 有 ±1min 时钟容差与 5min 有效期）

## 常见问题
- **签名校验失败**：metadata 中的证书与签名所用私钥不匹配，或 metadata 未更新到最新证书（重新上传 metadata）。
- **「无权访问」/「Role not found」**：IdP ARN 与角色 ARN 主账号 ID 不一致，或角色未信任该 IdP。
- **角色控制台报 Provider ARN 缺失**：阿里云侧 IdP 尚未创建，或 IdP ARN 未填入角色表单的 Provider ARN 字段。
- **登录后 403/空白页**：用户未绑定角色、角色被停用。
