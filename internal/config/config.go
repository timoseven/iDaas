// Package config 从环境变量加载 iDaas 运行配置
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config 保存全部运行时配置
type Config struct {
	ListenAddr string
	DBPath     string
	SecretKey  string

	// SAML 2.0 IdP（与具体云无关；各云规格由 internal/saml/clouds.go 内置）
	SAMLEntityID  string
	SAMLBaseURL   string
	SAMLCertPath  string
	SAMLKeyPath   string
	SAMLValidMins int
	SAMLOrgName   string
	SAMLOrgDisp   string
	SAMLOrgURL    string
	SAMLContact   string
}

// Load 从环境变量加载配置，缺失项使用默认值
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr: env("LISTEN_ADDR", ":8088"),
		DBPath:     env("DB_PATH", "idaas.db"),
		SecretKey:  env("SECRET_KEY", "dev-insecure-key-change-me"),

		SAMLEntityID:  env("SAML_ENTITY_ID", "http://localhost:8088/saml/metadata"),
		SAMLBaseURL:   strings.TrimRight(env("SAML_BASE_URL", "http://localhost:8088"), "/"),
		SAMLCertPath:  env("SAML_CERT_PATH", "certs/idp.crt"),
		SAMLKeyPath:   env("SAML_KEY_PATH", "certs/idp.key"),
		SAMLValidMins: envInt("SAML_ASSERTION_VALID_MINUTES", 5),
		SAMLOrgName:   env("SAML_ORG_NAME", "iDaas"),
		SAMLOrgDisp:   env("SAML_ORG_DISPLAY_NAME", "iDaas Identity Provider"),
		SAMLOrgURL:    env("SAML_ORG_URL", ""),
		SAMLContact:   env("SAML_CONTACT_EMAIL", ""),
	}
	if cfg.SecretKey == "dev-insecure-key-change-me" {
		fmt.Fprintln(os.Stderr, "警告：使用默认 SECRET_KEY，请通过环境变量设置强随机值")
	}
	return cfg, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
