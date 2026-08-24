package webserver

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"idaas/internal/auth"
	"idaas/internal/models"
	"idaas/internal/saml"
	"idaas/internal/store"
)

// userForm 用于 user_form.html 的表单回显
type userForm struct {
	Username    string
	DisplayName string
	Email       string
	IsAdmin     bool
	IsActive    bool
}

// roleForm 用于 role_form.html 的表单回显
type roleForm struct {
	Name        string
	Cloud       string
	ARN         string
	ProviderARN string
	Description string
	IsActive    bool
}

// ------------------------------------------------------------
// 仪表盘
// ------------------------------------------------------------

func (s *Server) adminDashboard(w http.ResponseWriter, r *http.Request) {
	users, _ := s.store.CountUsers()
	roles, _ := s.store.CountRoles()
	bindings, _ := s.store.CountBindings()
	admins, _ := s.store.CountAdmins()
	s.render(w, r, "admin/dashboard", map[string]any{
		"Stats": map[string]int{
			"Users":    users,
			"Roles":    roles,
			"Bindings": bindings,
			"Admins":   admins,
		},
	})
}

// ------------------------------------------------------------
// 用户
// ------------------------------------------------------------

func (s *Server) adminUsersList(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers()
	if err != nil {
		http.Error(w, "读取用户列表失败", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "admin/users", map[string]any{"Users": users})
}

func (s *Server) adminUserForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		// 新建
		s.render(w, r, "admin/user_form", map[string]any{
			"Action": "/admin/users/new",
			"Form":   userForm{IsActive: true},
		})
		return
	}
	uid, err := strconv.ParseUint(id, 10, 64)
	if err != nil || uid == 0 {
		http.Error(w, "无效的用户 ID", http.StatusBadRequest)
		return
	}
	u, err := s.store.GetUser(uid)
	if err != nil {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}
	bindings, _ := s.store.ListBindingsByUserRaw(uid)
	available, _ := s.store.AvailableRoles(uid)
	s.render(w, r, "admin/user_form", map[string]any{
		"User":           u,
		"Action":         "/admin/users/" + id + "/edit",
		"Form":           userForm{Username: u.Username, DisplayName: u.DisplayName, Email: u.Email, IsAdmin: u.IsAdmin, IsActive: u.IsActive},
		"Bindings":       bindings,
		"AvailableRoles": available,
	})
}

func (s *Server) adminUserCreate(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(r); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	form := readUserForm(r)
	renderErr := func(msg string) {
		s.render(w, r, "admin/user_form", map[string]any{
			"Action": "/admin/users/new",
			"Form":   form.userForm,
			"Error":  msg,
		})
	}
	if strings.TrimSpace(form.Username) == "" || form.passwordRaw == "" {
		renderErr("用户名和密码不能为空")
		return
	}
	hash, err := auth.HashPassword(form.passwordRaw)
	if err != nil {
		renderErr("密码哈希失败")
		return
	}
	u := &models.User{
		Username:     strings.TrimSpace(form.Username),
		PasswordHash: hash,
		IsAdmin:      form.IsAdmin,
		IsActive:     form.IsActive,
		DisplayName:  form.DisplayName,
		Email:        form.Email,
	}
	if err := s.store.CreateUser(u); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			renderErr("用户名已存在")
			return
		}
		renderErr("创建用户失败：" + err.Error())
		return
	}
	setFlash(w, "success", "用户 "+u.Username+" 已创建")
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (s *Server) adminUserUpdate(w http.ResponseWriter, r *http.Request) {
	uid, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || uid == 0 {
		http.Error(w, "无效的用户 ID", http.StatusBadRequest)
		return
	}
	if err := parseForm(r); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	existing, err := s.store.GetUser(uid)
	if err != nil {
		http.Error(w, "用户不存在", http.StatusNotFound)
		return
	}
	form := readUserForm(r)
	willBeAdmin := form.IsAdmin
	willBeActive := form.IsActive

	renderErr := func(msg string) {
		bindings, _ := s.store.ListBindingsByUserRaw(uid)
		available, _ := s.store.AvailableRoles(uid)
		s.render(w, r, "admin/user_form", map[string]any{
			"User":           existing,
			"Action":         "/admin/users/" + r.PathValue("id") + "/edit",
			"Form":           form.userForm,
			"Bindings":       bindings,
			"AvailableRoles": available,
			"Error":          msg,
		})
	}

	// 最后一名管理员保护：禁止降级或停用最后一个管理员
	if existing.IsAdmin && (!willBeAdmin || !willBeActive) {
		if n, _ := s.store.CountAdmins(); n <= 1 {
			renderErr("不能降级或停用最后一个管理员账户")
			return
		}
	}

	existing.DisplayName = form.DisplayName
	existing.Email = form.Email
	existing.IsAdmin = willBeAdmin
	existing.IsActive = willBeActive
	if form.passwordRaw != "" {
		hash, err := auth.HashPassword(form.passwordRaw)
		if err != nil {
			renderErr("密码哈希失败")
			return
		}
		existing.PasswordHash = hash
	}
	if err := s.store.UpdateUser(existing); err != nil {
		renderErr("更新用户失败：" + err.Error())
		return
	}
	setFlash(w, "success", "用户 "+existing.Username+" 已更新")
	http.Redirect(w, r, "/admin/users/"+r.PathValue("id")+"/edit", http.StatusSeeOther)
}

func (s *Server) adminUserDelete(w http.ResponseWriter, r *http.Request) {
	uid, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || uid == 0 {
		http.Error(w, "无效的用户 ID", http.StatusBadRequest)
		return
	}
	current := auth.CurrentUser(r)
	if current.ID == uid {
		setFlash(w, "error", "不能删除当前登录的管理员账户")
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	u, err := s.store.GetUser(uid)
	if err != nil {
		setFlash(w, "error", "用户不存在")
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	if u.IsAdmin {
		if n, _ := s.store.CountAdmins(); n <= 1 {
			setFlash(w, "error", "不能删除最后一个管理员账户")
			http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
			return
		}
	}
	if err := s.store.DeleteUser(uid); err != nil {
		setFlash(w, "error", "删除用户失败："+err.Error())
		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}
	setFlash(w, "success", "用户 "+u.Username+" 已删除")
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// ------------------------------------------------------------
// 用户-角色绑定
// ------------------------------------------------------------

func (s *Server) adminBindingCreate(w http.ResponseWriter, r *http.Request) {
	uid, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || uid == 0 {
		http.Error(w, "无效的用户 ID", http.StatusBadRequest)
		return
	}
	if err := parseForm(r); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	rid, _ := strconv.ParseUint(r.FormValue("role_id"), 10, 64)
	if rid == 0 {
		setFlash(w, "error", "未选择角色")
		http.Redirect(w, r, "/admin/users/"+r.PathValue("id")+"/edit", http.StatusSeeOther)
		return
	}
	if _, err := s.store.GetRole(rid); err != nil {
		setFlash(w, "error", "角色不存在")
		http.Redirect(w, r, "/admin/users/"+r.PathValue("id")+"/edit", http.StatusSeeOther)
		return
	}
	b := &models.UserRole{
		UserID: uid,
		RoleID: rid,
		Remark: strings.TrimSpace(r.FormValue("remark")),
	}
	if err := s.store.CreateBinding(b); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			setFlash(w, "error", "该角色已绑定给此用户")
		} else {
			setFlash(w, "error", "创建绑定失败："+err.Error())
		}
	}
	http.Redirect(w, r, "/admin/users/"+r.PathValue("id")+"/edit", http.StatusSeeOther)
}

func (s *Server) adminBindingDelete(w http.ResponseWriter, r *http.Request) {
	uid, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	bid, _ := strconv.ParseUint(r.PathValue("bid"), 10, 64)
	if err != nil || uid == 0 || bid == 0 {
		http.Error(w, "无效的 ID", http.StatusBadRequest)
		return
	}
	b, err := s.store.GetBinding(bid)
	if err != nil || b.UserID != uid {
		setFlash(w, "error", "绑定不存在或不属于该用户")
		http.Redirect(w, r, "/admin/users/"+r.PathValue("id")+"/edit", http.StatusSeeOther)
		return
	}
	if err := s.store.DeleteBinding(bid); err != nil {
		setFlash(w, "error", "解绑失败："+err.Error())
	}
	http.Redirect(w, r, "/admin/users/"+r.PathValue("id")+"/edit", http.StatusSeeOther)
}

// ------------------------------------------------------------
// 角色
// ------------------------------------------------------------

func (s *Server) adminRolesList(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.ListRoles()
	if err != nil {
		http.Error(w, "读取角色列表失败", http.StatusInternalServerError)
		return
	}
	counts := map[uint64]int{}
	for _, role := range roles {
		n, _ := s.store.BindingCountByRole(role.ID)
		counts[role.ID] = n
	}
	s.render(w, r, "admin/roles", map[string]any{
		"Roles":      roles,
		"RoleCounts": counts,
	})
}

func (s *Server) adminRoleForm(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	cloudOpts := saml.CloudOptions()
	if id == "" {
		s.render(w, r, "admin/role_form", map[string]any{
			"Action":       "/admin/roles/new",
			"Form":         roleForm{Cloud: string(saml.CloudAliyun), IsActive: true},
			"CloudOptions": cloudOpts,
		})
		return
	}
	rid, err := strconv.ParseUint(id, 10, 64)
	if err != nil || rid == 0 {
		http.Error(w, "无效的角色 ID", http.StatusBadRequest)
		return
	}
	role, err := s.store.GetRole(rid)
	if err != nil {
		http.Error(w, "角色不存在", http.StatusNotFound)
		return
	}
	s.render(w, r, "admin/role_form", map[string]any{
		"Role":         role,
		"Action":       "/admin/roles/" + id + "/edit",
		"Form":         roleForm{Name: role.Name, Cloud: role.Cloud, ARN: role.ARN, ProviderARN: role.ProviderARN, Description: role.Description, IsActive: role.IsActive},
		"CloudOptions": cloudOpts,
	})
}

func (s *Server) adminRoleCreate(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(r); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	f := readRoleForm(r)
	cloudOpts := saml.CloudOptions()
	renderErr := func(msg string) {
		s.render(w, r, "admin/role_form", map[string]any{
			"Action":       "/admin/roles/new",
			"Form":         f,
			"CloudOptions": cloudOpts,
			"Error":        msg,
		})
	}
	if strings.TrimSpace(f.Name) == "" || strings.TrimSpace(f.ARN) == "" {
		renderErr("名称和 ARN 不能为空")
		return
	}
	spec, ok := saml.LookupCloud(saml.Cloud(f.Cloud))
	if !ok {
		renderErr("请选择有效的云厂商")
		return
	}
	if spec.NeedsProviderARN && strings.TrimSpace(f.ProviderARN) == "" {
		renderErr(spec.Label + " 需要填写 " + spec.ProviderLabel)
		return
	}
	role := &models.RamRole{
		Name:        strings.TrimSpace(f.Name),
		Cloud:       strings.TrimSpace(f.Cloud),
		ARN:         strings.TrimSpace(f.ARN),
		ProviderARN: strings.TrimSpace(f.ProviderARN),
		Description: strings.TrimSpace(f.Description),
		IsActive:    f.IsActive,
	}
	if err := s.store.CreateRole(role); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			renderErr("名称或 ARN 已存在")
			return
		}
		renderErr("创建角色失败：" + err.Error())
		return
	}
	setFlash(w, "success", "角色 "+role.Name+" 已创建")
	http.Redirect(w, r, "/admin/roles", http.StatusSeeOther)
}

func (s *Server) adminRoleUpdate(w http.ResponseWriter, r *http.Request) {
	rid, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || rid == 0 {
		http.Error(w, "无效的角色 ID", http.StatusBadRequest)
		return
	}
	if err := parseForm(r); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	existing, err := s.store.GetRole(rid)
	if err != nil {
		http.Error(w, "角色不存在", http.StatusNotFound)
		return
	}
	f := readRoleForm(r)
	cloudOpts := saml.CloudOptions()
	renderErr := func(msg string) {
		s.render(w, r, "admin/role_form", map[string]any{
			"Role":         existing,
			"Action":       "/admin/roles/" + r.PathValue("id") + "/edit",
			"Form":         f,
			"CloudOptions": cloudOpts,
			"Error":        msg,
		})
	}
	if strings.TrimSpace(f.Name) == "" || strings.TrimSpace(f.ARN) == "" {
		renderErr("名称和 ARN 不能为空")
		return
	}
	spec, ok := saml.LookupCloud(saml.Cloud(f.Cloud))
	if !ok {
		renderErr("请选择有效的云厂商")
		return
	}
	if spec.NeedsProviderARN && strings.TrimSpace(f.ProviderARN) == "" {
		renderErr(spec.Label + " 需要填写 " + spec.ProviderLabel)
		return
	}
	existing.Name = strings.TrimSpace(f.Name)
	existing.Cloud = strings.TrimSpace(f.Cloud)
	existing.ARN = strings.TrimSpace(f.ARN)
	existing.ProviderARN = strings.TrimSpace(f.ProviderARN)
	existing.Description = strings.TrimSpace(f.Description)
	existing.IsActive = f.IsActive
	if err := s.store.UpdateRole(existing); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			renderErr("名称或 ARN 已被其他角色占用")
			return
		}
		renderErr("更新角色失败：" + err.Error())
		return
	}
	setFlash(w, "success", "角色 "+existing.Name+" 已更新")
	http.Redirect(w, r, "/admin/roles", http.StatusSeeOther)
}

func (s *Server) adminRoleDelete(w http.ResponseWriter, r *http.Request) {
	rid, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil || rid == 0 {
		http.Error(w, "无效的角色 ID", http.StatusBadRequest)
		return
	}
	role, err := s.store.GetRole(rid)
	if err != nil {
		setFlash(w, "error", "角色不存在")
		http.Redirect(w, r, "/admin/roles", http.StatusSeeOther)
		return
	}
	if err := s.store.DeleteRole(rid); err != nil {
		setFlash(w, "error", "删除角色失败："+err.Error())
		http.Redirect(w, r, "/admin/roles", http.StatusSeeOther)
		return
	}
	setFlash(w, "success", "角色 "+role.Name+" 已删除")
	http.Redirect(w, r, "/admin/roles", http.StatusSeeOther)
}

// ------------------------------------------------------------
// 表单读取辅助
// ------------------------------------------------------------

// formPayload 同时承载表单字段与密码明文（不暴露到模板）
type formPayload struct {
	userForm
	passwordRaw string
}

func readUserForm(r *http.Request) formPayload {
	return formPayload{
		userForm: userForm{
			Username:    r.FormValue("username"),
			DisplayName: r.FormValue("display_name"),
			Email:       r.FormValue("email"),
			IsAdmin:     r.FormValue("is_admin") == "1",
			IsActive:    r.FormValue("is_active") == "1",
		},
		passwordRaw: r.FormValue("password"),
	}
}

func readRoleForm(r *http.Request) roleForm {
	return roleForm{
		Name:        r.FormValue("name"),
		Cloud:       r.FormValue("cloud"),
		ARN:         r.FormValue("arn"),
		ProviderARN: r.FormValue("provider_arn"),
		Description: r.FormValue("description"),
		IsActive:    r.FormValue("is_active") == "1",
	}
}
