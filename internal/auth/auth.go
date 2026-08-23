// Package auth 提供会话、CSRF、密码哈希与权限中间件
//
// 会话：服务端 bbolt 存储（bucketSessions），cookie 仅持有随机 session_id。
// CSRF：双提交 cookie 模式——GET 响应种 csrf_token cookie，模板渲染同名 token，
//
//	POST 请求校验 cookie 与表单字段一致。登录后 cookie 与会话内 token 对齐。
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"idaas/internal/models"
	"idaas/internal/store"
)

type contextKey string

const (
	ctxUser contextKey = "user"
	ctxCSRF contextKey = "csrf"
)

const (
	cookieSession = "idaas_session"
	cookieCSRF    = "csrf_token"
	sessionPath   = "/"
	sessionTTL    = 8 * time.Hour
	rememberTTL   = 30 * 24 * time.Hour
	csrfCookieTTL = 30 * 24 * time.Hour
)

// Service 认证服务
type Service struct {
	store *store.Store
}

// New 创建认证服务
func New(s *store.Store) *Service {
	return &Service{store: s}
}

// HashPassword 使用 bcrypt 哈希密码
func HashPassword(raw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(raw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// VerifyPassword 校验密码与哈希
func VerifyPassword(hash, raw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(raw)) == nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Middleware 加载会话/用户到上下文，并在 GET 上确保 CSRF cookie
func (a *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(cookieSession); err == nil && c.Value != "" {
			if sess, err := a.store.GetSession(c.Value); err == nil && sess.UserID > 0 {
				if u, err := a.store.GetUser(sess.UserID); err == nil {
					ctx := context.WithValue(r.Context(), ctxUser, u)
					ctx = context.WithValue(ctx, ctxCSRF, sess.CSRFToken)
					r = r.WithContext(ctx)
				}
			}
		}
		if r.Method == http.MethodGet {
			r = a.ensureCSRFCookie(w, r)
		}
		next.ServeHTTP(w, r)
	})
}

// ensureCSRFCookie 确保响应带 csrf_token cookie，并把 token 注入 ctx 供本次渲染读取
//
// 三种情况：
//  1. 请求已带 cookie：无需处理，CSRFToken 会从 cookie 读取
//  2. 已登录但 cookie 丢失：用会话内 token 重建 cookie，保持 cookie/会话/表单三者对齐
//  3. 未登录且无 cookie：生成新 token，种 cookie 并注入 ctx（否则本次渲染 {{.CSRFToken}} 为空，
//     会导致首次访问 /login 后 POST 因 form token 为空而校验失败）
func (a *Service) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) *http.Request {
	if c, err := r.Cookie(cookieCSRF); err == nil && c.Value != "" {
		return r
	}
	if v, ok := r.Context().Value(ctxCSRF).(string); ok && v != "" {
		http.SetCookie(w, &http.Cookie{
			Name: cookieCSRF, Value: v, Path: sessionPath,
			HttpOnly: false, SameSite: http.SameSiteLaxMode,
			MaxAge: int(csrfCookieTTL.Seconds()),
		})
		return r
	}
	tok, err := randomHex(16)
	if err != nil {
		return r
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieCSRF,
		Value:    tok,
		Path:     sessionPath,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(csrfCookieTTL.Seconds()),
	})
	ctx := context.WithValue(r.Context(), ctxCSRF, tok)
	return r.WithContext(ctx)
}

// CSRFToken 返回当前请求可用的 CSRF token（已登录用户用会话内 token，未登录用 cookie）
func CSRFToken(r *http.Request) string {
	if v, ok := r.Context().Value(ctxCSRF).(string); ok && v != "" {
		return v
	}
	if c, err := r.Cookie(cookieCSRF); err == nil {
		return c.Value
	}
	return ""
}

// VerifyCSRF 校验写请求的 CSRF token（双提交）
func (a *Service) VerifyCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch:
			cookieTok := ""
			if c, err := r.Cookie(cookieCSRF); err == nil {
				cookieTok = c.Value
			}
			formTok := r.FormValue("csrf_token")
			if formTok == "" {
				formTok = r.Header.Get("X-CSRF-Token")
			}
			if cookieTok == "" || formTok == "" || cookieTok != formTok {
				http.Error(w, "CSRF 校验失败", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// Login 创建会话并下发 cookie
func (a *Service) Login(w http.ResponseWriter, r *http.Request, userID uint64, remember bool) error {
	csrfTok, err := randomHex(16)
	if err != nil {
		return err
	}
	id, err := randomHex(32)
	if err != nil {
		return err
	}
	ttl := sessionTTL
	if remember {
		ttl = rememberTTL
	}
	sess := &store.Session{
		ID:        id,
		UserID:    userID,
		CSRFToken: csrfTok,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(ttl),
	}
	if err := a.store.CreateSession(sess); err != nil {
		return err
	}
	// CSRF cookie 与会话内 token 对齐，便于双提交校验
	http.SetCookie(w, &http.Cookie{
		Name: cookieCSRF, Value: csrfTok, Path: sessionPath,
		HttpOnly: false, SameSite: http.SameSiteLaxMode,
		MaxAge: int(ttl.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name: cookieSession, Value: id, Path: sessionPath,
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		MaxAge: int(ttl.Seconds()),
	})
	return nil
}

// Logout 清除会话与 cookie
func (a *Service) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieSession); err == nil && c.Value != "" {
		_ = a.store.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieSession, Path: sessionPath, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: cookieCSRF, Path: sessionPath, MaxAge: -1})
}

// CurrentUser 从上下文取当前用户（无则 nil）
func CurrentUser(r *http.Request) *models.User {
	if v, ok := r.Context().Value(ctxUser).(*models.User); ok {
		return v
	}
	return nil
}

// IsAuthenticated 是否已登录
func IsAuthenticated(r *http.Request) bool {
	return CurrentUser(r) != nil
}

// RequireLogin 要求登录，否则跳转 /login
func RequireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !IsAuthenticated(r) {
			http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// RequireAdmin 要求管理员
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := CurrentUser(r)
		if u == nil || !u.IsAdmin {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}
