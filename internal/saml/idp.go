// Package saml 实现 iDaas 作为 SAML 2.0 IdP：metadata 生成、IdP-initiated
// SAMLResponse 构造与签名（rsa-sha256 + enveloped xmldsig），目标为阿里云 ACS。
//
// 复用 github.com/crewjam/saml 的数据类型（Assertion/Response/Attribute 等）
// 与签名上下文（github.com/russellhaering/goxmldsig），但不走其
// IdpAuthnRequest/ServiceProviderProvider 抽象——因为本用例为单一固定 SP（阿里云）+ IdP-initiated。
package saml

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/beevik/etree"
	saml "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// 阿里云约定的 SAML 属性名
const (
	AttrRole        = "https://www.aliyun.com/SAML-Role/Attributes/Role"
	AttrSessionName = "https://www.aliyun.com/SAML-Role/Attributes/RoleSessionName"
)

const (
	nameIDUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	cmBearer          = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
	authnCtxClass     = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	issuerFormat      = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	xmlDecl           = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"
)

// Config SAML IdP 配置
type Config struct {
	EntityID  string
	BaseURL   string
	ACSURL    string
	CertPath  string
	KeyPath   string
	IdpARN    string
	ValidMins int
	OrgName   string
	OrgDisp   string
	OrgURL    string
	Contact   string
}

// IdP 已加载证书/私钥并初始化签名上下文的 IdP
type IdP struct {
	cfg        Config
	cert       *x509.Certificate
	key        *rsa.PrivateKey
	signingCtx *dsig.SigningContext
	crewjam    saml.IdentityProvider // 仅用于生成 metadata
}

// New 加载证书/私钥，初始化 IdP 与签名上下文
func New(cfg Config) (*IdP, error) {
	certPEM, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		return nil, fmt.Errorf("读取证书失败：%w", err)
	}
	keyPEM, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("读取私钥失败：%w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, errors.New("证书不是合法的 PEM 格式")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书失败：%w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("私钥不是合法的 PEM 格式")
	}
	var key *rsa.PrivateKey
	switch {
	case strings.Contains(keyBlock.Type, "RSA"):
		key, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("解析 PKCS1 私钥失败：%w", err)
		}
	default:
		k, perr := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("解析 PKCS8 私钥失败：%w", perr)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("私钥不是 RSA 私钥")
		}
		key = rk
	}

	keyStore := dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	})
	sc := dsig.NewDefaultSigningContext(keyStore)
	sc.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := sc.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		return nil, fmt.Errorf("设置签名算法失败：%w", err)
	}

	metadataURL, err := url.Parse(cfg.EntityID)
	if err != nil {
		return nil, fmt.Errorf("EntityID 不是合法 URL：%w", err)
	}
	ssoURL, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/") + "/saml/sso")
	if err != nil {
		return nil, fmt.Errorf("BaseURL 不是合法 URL：%w", err)
	}

	return &IdP{
		cfg:        cfg,
		cert:       cert,
		key:        key,
		signingCtx: sc,
		crewjam: saml.IdentityProvider{
			Certificate: cert,
			Key:         key,
			MetadataURL: *metadataURL,
			SSOURL:      *ssoURL,
		},
	}, nil
}

// CertPEM 返回 IdP 证书 PEM 文本（可用于调试展示）
func (i *IdP) CertPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.cert.Raw}))
}

// Metadata 生成 IdP metadata XML 字符串（供阿里云上传）
func (i *IdP) Metadata() (string, error) {
	ed := i.crewjam.Metadata()
	ed.Organization = &saml.Organization{
		OrganizationNames:        []saml.LocalizedName{{Lang: "en", Value: i.cfg.OrgName}},
		OrganizationDisplayNames: []saml.LocalizedName{{Lang: "en", Value: i.cfg.OrgDisp}},
		OrganizationURLs:         []saml.LocalizedURI{{Lang: "en", Value: orgURL(i.cfg.OrgURL, i.cfg.BaseURL)}},
	}
	if i.cfg.Contact != "" {
		ed.ContactPerson = &saml.ContactPerson{
			ContactType:    "technical",
			EmailAddresses: []string{i.cfg.Contact},
		}
	}
	data, err := xml.MarshalIndent(ed, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化 metadata 失败：%w", err)
	}
	return xmlDecl + string(data), nil
}

// BuildResponse 构造并签名 IdP-initiated SAMLResponse，返回 XML 字符串
func (i *IdP) BuildResponse(username, roleARN string) (string, error) {
	if i.cfg.IdpARN == "" {
		return "", errors.New("未配置 SAML_IDP_ARN（阿里云侧创建 SAML IdP 后填入）")
	}
	now := time.Now().UTC()
	notBefore := now.Add(-1 * time.Minute)
	notOnOrAfter := now.Add(time.Duration(i.cfg.ValidMins) * time.Minute)

	assertionID := "id-" + randomHex(20)
	responseID := "id-" + randomHex(20)

	assertion := &saml.Assertion{
		ID:           assertionID,
		IssueInstant: now,
		Version:      "2.0",
		Issuer:       saml.Issuer{Format: issuerFormat, Value: i.cfg.EntityID},
		Subject: &saml.Subject{
			NameID: &saml.NameID{Format: nameIDUnspecified, Value: username},
			SubjectConfirmations: []saml.SubjectConfirmation{{
				Method: cmBearer,
				SubjectConfirmationData: &saml.SubjectConfirmationData{
					NotOnOrAfter: notOnOrAfter,
					Recipient:    i.cfg.ACSURL,
				},
			}},
		},
		Conditions: &saml.Conditions{NotBefore: notBefore, NotOnOrAfter: notOnOrAfter},
		AuthnStatements: []saml.AuthnStatement{{
			AuthnInstant:        now,
			SessionIndex:        assertionID,
			SessionNotOnOrAfter: &notOnOrAfter,
			AuthnContext: saml.AuthnContext{
				AuthnContextClassRef: &saml.AuthnContextClassRef{Value: authnCtxClass},
			},
		}},
		AttributeStatements: []saml.AttributeStatement{{
			Attributes: []saml.Attribute{
				{Name: AttrRole, Values: []saml.AttributeValue{{Type: "xs:string", Value: i.cfg.IdpARN + "," + roleARN}}},
				{Name: AttrSessionName, Values: []saml.AttributeValue{{Type: "xs:string", Value: username}}},
			},
		}},
	}

	// 1. 签名 Assertion（enveloped）
	assertionEl := assertion.Element()
	signedAssertionEl, err := i.signingCtx.SignEnveloped(assertionEl)
	if err != nil {
		return "", fmt.Errorf("签名 Assertion 失败：%w", err)
	}
	sigEl := signedAssertionEl.ChildElements()[len(signedAssertionEl.ChildElements())-1]
	assertion.Signature = sigEl
	signedAssertionEl = assertion.Element()

	// 2. 构造 Response（Issuer, Signature, Status），追加已签名 Assertion
	response := &saml.Response{
		ID:           responseID,
		Destination:  i.cfg.ACSURL,
		IssueInstant: now,
		Version:      "2.0",
		Issuer:       &saml.Issuer{Format: issuerFormat, Value: i.cfg.EntityID},
		Status:       saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
	}
	responseEl := response.Element()
	responseEl.AddChild(signedAssertionEl)

	// 3. 签名 Response（enveloped）
	signedResponseEl, err := i.signingCtx.SignEnveloped(responseEl)
	if err != nil {
		return "", fmt.Errorf("签名 Response 失败：%w", err)
	}
	respSigEl := signedResponseEl.ChildElements()[len(signedResponseEl.ChildElements())-1]
	response.Signature = respSigEl
	responseEl = response.Element()
	responseEl.AddChild(signedAssertionEl)

	// 4. 序列化（etree Element.WriteTo 仅输出元素，不含声明，手动补充）
	var buf bytes.Buffer
	buf.WriteString(xmlDecl)
	responseEl.WriteTo(&buf, &etree.WriteSettings{})
	return buf.String(), nil
}

func orgURL(env, base string) string {
	if env != "" {
		return env
	}
	return base
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// 极小概率；回退到基于时间
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
