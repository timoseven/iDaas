// Package saml 云厂商 SAML 规格预设
//
// 各云通过 SAML 联合登录到控制台时，AttributeStatement 中的属性名、Role 属性值的拼接顺序、
// ACS URL 都不同。本文件内置 6 个云的公开规格，BuildResponse 按 role.Cloud 派发。
//
// 添加新云：在 clouds 注册表加一个 CloudSpec 即可，无需改签名逻辑。
package saml

import "strings"

// Cloud 云厂商标识（用作 role.Cloud 取值）
type Cloud string

const (
	CloudAliyun  Cloud = "aliyun"
	CloudTencent Cloud = "tencent"
	CloudAWS     Cloud = "aws"
	CloudVolc    Cloud = "volc"
	CloudAzure   Cloud = "azure"
	CloudGCP     Cloud = "gcp"
)

// roleOrder 表示 Role 属性值中 RoleARN 与 ProviderARN 的拼接顺序
type roleOrder int

const (
	// orderProviderFirst: "<ProviderARN>,<RoleARN>" —— 阿里云、火山引擎
	orderProviderFirst roleOrder = iota
	// orderRoleFirst: "<RoleARN>,<ProviderARN>" —— AWS、腾讯云
	orderRoleFirst
	// orderNone: 不构造 Role 属性（仅 NameID 即可登录）—— Azure、GCP
	orderNone
)

// CloudSpec 单个云的 SAML 规格预设
type CloudSpec struct {
	// Label 中文显示名（用于后台下拉、门户分组标题）
	Label string
	// ACSURL 该云 AssertionConsumerService URL（固定值，来自各云公开文档）
	ACSURL string
	// RoleAttrName 扮演角色用的 SAML 属性名；空表示该云不使用 Role 属性
	RoleAttrName string
	// SessionAttrName 会话名/登录名 SAML 属性名；空表示用 NameID 即可
	SessionAttrName string
	// order Role 属性值中 RoleARN 与 ProviderARN 的顺序
	order roleOrder
	// NeedsProviderARN 该云是否需要第二标识（IdP ARN / Principal ARN / Provider ARN）
	NeedsProviderARN bool
	// ProviderLabel 第二标识在后台表单中的显示名（如 "IdP ARN" / "Principal ARN"）
	ProviderLabel string
	// providerPlaceholder 表单 placeholder 提示
	providerPlaceholder string
	// arnLabel Role ARN 字段在后台表单中的显示名（多数云是 "Role ARN"，Azure 是 "应用 Entity ID"）
	arnLabel string
	// arnPlaceholder Role ARN 字段 placeholder
	arnPlaceholder string
	// fixedAudience 固定 Audience 值或模板；非空时优先使用，空则按 order 派发。
	// 支持 {accountId} 占位符，会从 ARN 中提取账号 ID 替换（阿里云）。
	fixedAudience string
}

// clouds 全部内置云预设
var clouds = map[Cloud]CloudSpec{
	CloudAliyun: {
		Label:               "阿里云",
		ACSURL:              "https://signin.aliyun.com/saml/SSO",
		RoleAttrName:        "https://www.aliyun.com/SAML-Role/Attributes/Role",
		SessionAttrName:     "https://www.aliyun.com/SAML-Role/Attributes/RoleSessionName",
		order:               orderProviderFirst,
		NeedsProviderARN:    true,
		ProviderLabel:       "IdP ARN",
		providerPlaceholder: "acs:ram::<主账号ID>:saml-provider/<IdP名>",
		arnLabel:            "Role ARN",
		arnPlaceholder:      "acs:ram::<主账号ID>:role/<角色名>",
		fixedAudience:       "https://signin.aliyun.com/{accountId}/saml/SSO",
	},
	CloudTencent: {
		Label:               "腾讯云",
		ACSURL:              "https://cloud.tencent.com/saml/sso",
		RoleAttrName:        "https://cloud.tencent.com/SAML/Attributes/Role",
		SessionAttrName:     "https://cloud.tencent.com/SAML/Attributes/RoleSessionName",
		order:               orderRoleFirst,
		NeedsProviderARN:    true,
		ProviderLabel:       "SAML Provider",
		providerPlaceholder: "qcs:cam::<ownerUin>:saml:provider/<provider名>",
		arnLabel:            "Role ARN",
		arnPlaceholder:      "qcs:cam::<ownerUin>:role/<角色名>",
	},
	CloudAWS: {
		Label:               "AWS",
		ACSURL:              "https://signin.aws.amazon.com/saml",
		RoleAttrName:        "https://aws.amazon.com/SAML/Attributes/Role",
		SessionAttrName:     "https://aws.amazon.com/SAML/Attributes/RoleSessionName",
		order:               orderRoleFirst,
		NeedsProviderARN:    true,
		ProviderLabel:       "Principal ARN (SAML Provider)",
		providerPlaceholder: "arn:aws:iam::<account>:saml-provider/<provider名>",
		arnLabel:            "Role ARN",
		arnPlaceholder:      "arn:aws:iam::<account>:role/<角色名>",
	},
	CloudVolc: {
		Label:               "火山引擎",
		ACSURL:              "https://signin.volcengine.com/saml/SSO",
		RoleAttrName:        "https://www.volcengine.com/SAML/Attributes/Role",
		SessionAttrName:     "https://www.volcengine.com/SAML/Attributes/RoleSessionName",
		order:               orderProviderFirst,
		NeedsProviderARN:    true,
		ProviderLabel:       "Trusted Principal",
		providerPlaceholder: "acs:iam::<accountID>:saml-provider/<provider名>",
		arnLabel:            "Role ARN",
		arnPlaceholder:      "acs:iam::<accountID>:role/<角色名>",
	},
	CloudAzure: {
		// Azure AD 通过 Enterprise Application 联合登录，NameID 即登录身份，
		// 应用内部决定权限，不需要 Role 扮演属性。
		Label:            "Azure",
		ACSURL:           "https://login.microsoftonline.com/<tenant>/saml2",
		RoleAttrName:     "",
		SessionAttrName:  "",
		order:            orderNone,
		NeedsProviderARN: false,
		ProviderLabel:    "",
		arnLabel:         "应用 Entity ID / Identifier",
		arnPlaceholder:   "https://<your-app>.azurewebsites.net",
	},
	CloudGCP: {
		// GCP 通过 Workforce Identity Pool 联合，NameID 即外部身份，
		// GCP 端配置 Workforce Pool 信任该 IdP，无 Role 属性。
		Label:            "Google GCP",
		ACSURL:           "https://www.googleapis.com/cloud-identity/saml/acs",
		RoleAttrName:     "",
		SessionAttrName:  "",
		order:            orderNone,
		NeedsProviderARN: false,
		ProviderLabel:    "",
		arnLabel:         "Workforce Pool Provider ID",
		arnPlaceholder:   "locations/global/workforcePools/<pool>/providers/<provider>",
	},
}

// LookupCloud 返回指定云的规格；未知云返回 ok=false
func LookupCloud(c Cloud) (CloudSpec, bool) {
	v, ok := clouds[c]
	return v, ok
}

// AllClouds 返回全部内置云（用于后台下拉选项）
func AllClouds() []Cloud {
	return []Cloud{CloudAliyun, CloudTencent, CloudAWS, CloudVolc, CloudAzure, CloudGCP}
}

// CloudOptions 返回 (cloud 标识, 显示名) 列表，用于模板下拉
func CloudOptions() []struct {
	Value string
	Label string
} {
	out := make([]struct {
		Value string
		Label string
	}, 0, len(clouds))
	for _, c := range AllClouds() {
		spec, _ := clouds[c]
		out = append(out, struct {
			Value string
			Label string
		}{Value: string(c), Label: spec.Label})
	}
	return out
}

// roleAttrValue 按 roleARN + providerARN 与云规格构造 Role 属性值
// orderNone 时返回空串表示不输出 Role 属性
func (spec CloudSpec) roleAttrValue(roleARN, providerARN string) string {
	switch spec.order {
	case orderProviderFirst:
		return providerARN + "," + roleARN
	case orderRoleFirst:
		return roleARN + "," + providerARN
	default:
		return ""
	}
}

// audience 返回该云在 Conditions/AudienceRestriction 中期望的 Audience 值。
//   - 若 fixedAudience 非空，优先使用；支持 {accountId} 占位符（阿里云从 ARN 提取账号 ID 替换）
//   - 阿里云/火山引擎（orderProviderFirst）：Audience = ProviderARN（IdP ARN / Trusted Principal）
//   - AWS/腾讯云（orderRoleFirst）：Audience = 该云 ACS URL
//   - Azure/GCP（orderNone）：Audience = SP 自身标识（Azure 应用 Entity ID / GCP Workforce Provider，即 roleARN）
func (spec CloudSpec) audience(roleARN, providerARN string) string {
	if spec.fixedAudience != "" {
		if strings.Contains(spec.fixedAudience, "{accountId}") {
			if acc := extractAccountID(roleARN, providerARN); acc != "" {
				return strings.ReplaceAll(spec.fixedAudience, "{accountId}", acc)
			}
		} else {
			return spec.fixedAudience
		}
	}
	switch spec.order {
	case orderProviderFirst:
		return providerARN
	case orderRoleFirst:
		return spec.ACSURL
	default:
		return roleARN
	}
}

// extractAccountID 从 ARN 中提取主账号 ID。
// 阿里云 ARN 格式：acs:ram::<accountId>:role/<name> 或 acs:ram::<accountId>:saml-provider/<name>
func extractAccountID(arns ...string) string {
	for _, arn := range arns {
		parts := strings.Split(arn, ":")
		if len(parts) >= 4 && parts[0] == "acs" && parts[3] != "" {
			return parts[3]
		}
	}
	return ""
}
