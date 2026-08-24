// Package webserver 实现 iDaas 的 HTTP 层：路由、模板渲染、静态资源、flash。
//
// 路由使用 Go 1.22 增强型 ServeMux（"GET /path" / "POST /path/{id}/x"）。
// 中间件链：auth.Middleware（加载会话+种 CSRF cookie）→ auth.VerifyCSRF（校验写请求）→ mux。
// 模板：html/template + embed.FS，base.html 用 {{define "base"}}+{{block}} 布局，每页 ParseFS(base+page)。
// Flash：一次性 cookie（flash/flash_kind），render 读取后清除，用于 PRG 后的提示消息。
package webserver

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"idaas/internal/auth"
	"idaas/internal/config"
	"idaas/internal/saml"
	"idaas/internal/store"
)

//go:embed all:web/templates
var templateFS embed.FS

//go:embed all:web/static
var staticFS embed.FS

const (
	flashCookie     = "flash"
	flashKindCookie = "flash_kind"
)

// 每个页面解析时所需的模板文件列表（base + 页面）
var pageFiles = map[string][]string{
	"login":            {"web/templates/base.html", "web/templates/login.html"},
	"portal/dashboard": {"web/templates/base.html", "web/templates/portal/dashboard.html"},
	"portal/saml_post": {"web/templates/base.html", "web/templates/portal/saml_post.html"},
	"admin/dashboard":  {"web/templates/base.html", "web/templates/admin/dashboard.html"},
	"admin/users":      {"web/templates/base.html", "web/templates/admin/users.html"},
	"admin/user_form":  {"web/templates/base.html", "web/templates/admin/user_form.html"},
	"admin/roles":      {"web/templates/base.html", "web/templates/admin/roles.html"},
	"admin/role_form":  {"web/templates/base.html", "web/templates/admin/role_form.html"},
}

// Server HTTP 服务器
type Server struct {
	cfg       *config.Config
	store     *store.Store
	auth      *auth.Service
	idp       *saml.IdP
	templates map[string]*template.Template
	mux       *http.ServeMux
}

// New 构造服务器并预解析模板、注册路由
func New(cfg *config.Config, st *store.Store, authSvc *auth.Service, idp *saml.IdP) (*Server, error) {
	s := &Server{
		cfg:   cfg,
		store: st,
		auth:  authSvc,
		idp:   idp,
	}
	if err := s.loadTemplates(); err != nil {
		return nil, err
	}
	s.routes()
	return s, nil
}

func (s *Server) loadTemplates() error {
	funcMap := template.FuncMap{
		"hasPrefix": func(s, prefix string) bool { return strings.HasPrefix(s, prefix) },
		"formatDate": func(t time.Time) string {
			if t.IsZero() {
				return "—"
			}
			return t.Local().Format("2006-01-02 15:04")
		},
		"cloudLabel": func(c string) string {
			spec, ok := saml.LookupCloud(saml.Cloud(c))
			if !ok || spec.Label == "" {
				return c
			}
			return spec.Label
		},
	}
	templates := make(map[string]*template.Template, len(pageFiles))
	for name, files := range pageFiles {
		t, err := template.New("").Funcs(funcMap).ParseFS(templateFS, files...)
		if err != nil {
			return fmt.Errorf("解析模板 %s 失败：%w", name, err)
		}
		templates[name] = t
	}
	s.templates = templates
	return nil
}

// routes 注册全部路由
func (s *Server) routes() {
	mux := http.NewServeMux()

	// 静态资源
	staticSub, _ := fs.Sub(staticFS, "web/static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// 公开：SAML metadata
	mux.HandleFunc("GET /saml/metadata", s.samlMetadata)

	// 登录/登出
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("GET /logout", s.logout)

	// 门户（需登录）
	mux.HandleFunc("GET /", auth.RequireLogin(s.portalDashboard))
	mux.HandleFunc("POST /role/{id}/console", auth.RequireLogin(s.samlLogin))

	// 后台管理（需管理员）
	mux.HandleFunc("GET /admin", auth.RequireLogin(auth.RequireAdmin(s.adminDashboard)))
	mux.HandleFunc("GET /admin/users", auth.RequireLogin(auth.RequireAdmin(s.adminUsersList)))
	mux.HandleFunc("GET /admin/users/new", auth.RequireLogin(auth.RequireAdmin(s.adminUserForm)))
	mux.HandleFunc("POST /admin/users/new", auth.RequireLogin(auth.RequireAdmin(s.adminUserCreate)))
	mux.HandleFunc("GET /admin/users/{id}/edit", auth.RequireLogin(auth.RequireAdmin(s.adminUserForm)))
	mux.HandleFunc("POST /admin/users/{id}/edit", auth.RequireLogin(auth.RequireAdmin(s.adminUserUpdate)))
	mux.HandleFunc("POST /admin/users/{id}/delete", auth.RequireLogin(auth.RequireAdmin(s.adminUserDelete)))
	mux.HandleFunc("POST /admin/users/{id}/bindings", auth.RequireLogin(auth.RequireAdmin(s.adminBindingCreate)))
	mux.HandleFunc("POST /admin/users/{id}/bindings/{bid}/delete", auth.RequireLogin(auth.RequireAdmin(s.adminBindingDelete)))

	mux.HandleFunc("GET /admin/roles", auth.RequireLogin(auth.RequireAdmin(s.adminRolesList)))
	mux.HandleFunc("GET /admin/roles/new", auth.RequireLogin(auth.RequireAdmin(s.adminRoleForm)))
	mux.HandleFunc("POST /admin/roles/new", auth.RequireLogin(auth.RequireAdmin(s.adminRoleCreate)))
	mux.HandleFunc("GET /admin/roles/{id}/edit", auth.RequireLogin(auth.RequireAdmin(s.adminRoleForm)))
	mux.HandleFunc("POST /admin/roles/{id}/edit", auth.RequireLogin(auth.RequireAdmin(s.adminRoleUpdate)))
	mux.HandleFunc("POST /admin/roles/{id}/delete", auth.RequireLogin(auth.RequireAdmin(s.adminRoleDelete)))

	s.mux = mux
}

// Handler 返回装配中间件后的根 HTTP Handler
func (s *Server) Handler() http.Handler {
	// auth.Middleware：加载会话+种 CSRF cookie（GET）
	// auth.VerifyCSRF：校验写请求的 CSRF token（双提交 cookie）
	return s.auth.Middleware(s.auth.VerifyCSRF(s.mux))
}

// render 渲染页面，注入公共数据（CSRFToken/User/CurrentURL/Flash）
func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["CSRFToken"] = auth.CSRFToken(r)
	data["User"] = auth.CurrentUser(r)
	data["CurrentURL"] = r.URL.Path

	if c, err := r.Cookie(flashCookie); err == nil && c.Value != "" {
		data["Flash"] = c.Value
		kind := ""
		if kc, err := r.Cookie(flashKindCookie); err == nil {
			kind = kc.Value
		}
		data["FlashKind"] = kind
		// 读取即清除
		http.SetCookie(w, &http.Cookie{Name: flashCookie, Path: "/", MaxAge: -1})
		http.SetCookie(w, &http.Cookie{Name: flashKindCookie, Path: "/", MaxAge: -1})
	}

	t, ok := s.templates[name]
	if !ok {
		http.Error(w, "内部错误：未知模板 "+name, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "base", data); err != nil {
		// Execute 写入失败时通常已部分输出，记录到 stderr
		fmt.Printf("渲染模板 %s 失败：%v\n", name, err)
	}
}

// setFlash 设置一次性 flash 消息（PRG 模式下重定向前调用）
func setFlash(w http.ResponseWriter, kind, msg string) {
	http.SetCookie(w, &http.Cookie{
		Name: flashCookie, Value: msg, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 60,
	})
	http.SetCookie(w, &http.Cookie{
		Name: flashKindCookie, Value: kind, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 60,
	})
}

// parseForm 解析表单并返回精简错误处理
func parseForm(r *http.Request) error {
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("解析表单失败：%w", err)
	}
	return nil
}
