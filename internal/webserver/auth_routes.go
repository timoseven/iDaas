package webserver

import (
	"net/http"
	"strings"

	"idaas/internal/auth"
)

// loginForm GET /login
func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	if auth.IsAuthenticated(r) {
		http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", map[string]any{
		"Next":     r.URL.Query().Get("next"),
		"Username": "",
	})
}

// loginSubmit POST /login
func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := parseForm(r); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	next := safeNext(r.FormValue("next"))
	remember := r.FormValue("remember") == "1"

	renderErr := func(msg string) {
		s.render(w, r, "login", map[string]any{
			"Error":    msg,
			"Username": username,
			"Next":     next,
		})
	}

	if username == "" || password == "" {
		renderErr("用户名和密码不能为空")
		return
	}
	user, err := s.store.GetUserByUsername(username)
	if err != nil || !user.IsActive || !auth.VerifyPassword(user.PasswordHash, password) {
		renderErr("用户名或密码错误，或账户已被停用")
		return
	}
	if err := s.auth.Login(w, r, user.ID, remember); err != nil {
		renderErr("创建会话失败，请重试")
		return
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// logout GET /logout
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.auth.Logout(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// safeNext 规范化重定向目标，防止开放重定向
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		return "/"
	}
	return next
}
