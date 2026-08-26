package webserver

import (
	"encoding/base64"
	"net/http"
	"strconv"

	"idaas/internal/auth"
	"idaas/internal/models"
	"idaas/internal/saml"
)

// portalDashboard GET / 用户门户：按云分组列出当前用户的可用角色绑定
func (s *Server) portalDashboard(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(r)
	bindings, err := s.store.ListBindingsByUser(user.ID, true)
	if err != nil {
		http.Error(w, "读取角色绑定失败", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "portal/dashboard", map[string]any{
		"Groups": groupBindingsByCloud(bindings),
	})
}

// cloudGroup 门户分组展示结构
type cloudGroup struct {
	Cloud    string
	Label    string
	Bindings []*models.BindingView
}

// groupBindingsByCloud 把 ListBindingsByUser 返回的 BindingView 按 cloud 分组
func groupBindingsByCloud(bindings []*models.BindingView) []cloudGroup {
	byCloud := map[string]*cloudGroup{}
	order := []string{}
	for _, b := range bindings {
		c := b.Role.Cloud
		if c == "" {
			c = "aliyun"
		}
		g, exists := byCloud[c]
		if !exists {
			spec, _ := saml.LookupCloud(saml.Cloud(c))
			label := c
			if spec.Label != "" {
				label = spec.Label
			}
			g = &cloudGroup{Cloud: c, Label: label}
			byCloud[c] = g
			order = append(order, c)
		}
		g.Bindings = append(g.Bindings, b)
	}
	out := make([]cloudGroup, 0, len(order))
	for _, c := range order {
		out = append(out, *byCloud[c])
	}
	return out
}

// samlLogin POST /role/{id}/console 构造 IdP-initiated SAMLResponse 并自动提交到对应云 ACS
func (s *Server) samlLogin(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(r)

	roleID, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || roleID == 0 {
		http.Error(w, "无效的角色 ID", http.StatusBadRequest)
		return
	}
	if err := parseForm(r); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}

	role, err := s.store.GetRole(roleID)
	if err != nil {
		http.Error(w, "角色不存在", http.StatusNotFound)
		return
	}
	if !role.IsActive {
		http.Error(w, "该角色已被停用", http.StatusForbidden)
		return
	}

	// 安全检查：确认当前用户确有此角色绑定，防止伪造 binding_id / role_id
	bindingID, _ := strconv.ParseUint(r.FormValue("binding_id"), 10, 64)
	authorized := false
	if bindingID > 0 {
		if b, err := s.store.GetBinding(bindingID); err == nil &&
			b.UserID == user.ID && b.RoleID == role.ID {
			authorized = true
		}
	}
	if !authorized {
		// 回退：扫描该用户全部绑定核对
		if bindings, err := s.store.ListBindingsByUserRaw(user.ID); err == nil {
			for _, b := range bindings {
				if b.RoleID == role.ID {
					authorized = true
					break
				}
			}
		}
	}
	if !authorized {
		http.Error(w, "你没有访问该角色的权限", http.StatusForbidden)
		return
	}

	spec, ok := saml.LookupCloud(saml.Cloud(role.Cloud))
	if !ok {
		http.Error(w, "未知云厂商："+role.Cloud, http.StatusBadRequest)
		return
	}

	xmlResp, err := s.idp.BuildResponse(user.Username, saml.Role{
		Cloud:       role.Cloud,
		ARN:         role.ARN,
		ProviderARN: role.ProviderARN,
	})
	if err != nil {
		http.Error(w, "生成 SAML 断言失败："+err.Error(), http.StatusInternalServerError)
		return
	}

	s.render(w, r, "portal/saml_post", map[string]any{
		"SAMLResponse": base64.StdEncoding.EncodeToString([]byte(xmlResp)),
		"ACSURL":       spec.ACSURL,
	})
}

// samlDebug GET /role/{id}/saml-debug 调试端点：直接返回生成的 SAMLResponse XML
func (s *Server) samlDebug(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(r)
	roleID, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || roleID == 0 {
		http.Error(w, "无效的角色 ID", http.StatusBadRequest)
		return
	}
	role, err := s.store.GetRole(roleID)
	if err != nil {
		http.Error(w, "角色不存在", http.StatusNotFound)
		return
	}
	// 权限检查
	bindings, err := s.store.ListBindingsByUserRaw(user.ID)
	if err != nil {
		http.Error(w, "读取绑定失败", http.StatusInternalServerError)
		return
	}
	authorized := false
	for _, b := range bindings {
		if b.RoleID == role.ID {
			authorized = true
			break
		}
	}
	if !authorized {
		http.Error(w, "无权限", http.StatusForbidden)
		return
	}
	xmlResp, err := s.idp.BuildResponse(user.Username, saml.Role{
		Cloud:       role.Cloud,
		ARN:         role.ARN,
		ProviderARN: role.ProviderARN,
	})
	if err != nil {
		http.Error(w, "生成失败："+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Write([]byte(xmlResp))
}

// samlMetadata GET /saml/metadata 公开端点：返回 IdP metadata XML
func (s *Server) samlMetadata(w http.ResponseWriter, r *http.Request) {
	md, err := s.idp.Metadata()
	if err != nil {
		http.Error(w, "生成 metadata 失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Write([]byte(md))
}
