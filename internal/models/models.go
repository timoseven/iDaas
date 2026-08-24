// Package models 定义数据模型与序列化
package models

import "time"

// User 网站用户
type User struct {
	ID           uint64    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	IsAdmin      bool      `json:"is_admin"`
	IsActive     bool      `json:"is_active"`
	DisplayName  string    `json:"display_name,omitempty"`
	Email        string    `json:"email,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RamRole 云厂商角色（站点内登记，支持阿里云/腾讯云/AWS/火山引擎/Azure/GCP）
type RamRole struct {
	ID          uint64    `json:"id"`
	Name        string    `json:"name"`
	Cloud       string    `json:"cloud"`        // aliyun/tencent/aws/volc/azure/gcp
	ARN         string    `json:"arn"`          // 多数云为 Role ARN；Azure 为应用 Entity ID；GCP 为 Workforce Pool Provider ID
	ProviderARN string    `json:"provider_arn"` // IdP ARN / Principal ARN / SAML Provider；Azure/GCP 不需要
	Description string    `json:"description,omitempty"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// UserRole 用户-角色绑定
type UserRole struct {
	ID        uint64    `json:"id"`
	UserID    uint64    `json:"user_id"`
	RoleID    uint64    `json:"role_id"`
	Remark    string    `json:"remark,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// BindingView 用于门户展示：携带关联的角色
type BindingView struct {
	UserRole
	Role *RamRole `json:"role"`
}
