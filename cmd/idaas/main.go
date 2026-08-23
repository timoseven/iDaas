// Command idaas 启动 iDaas 身份提供者服务，或通过 createsuperuser 子命令创建管理员。
//
// 默认：加载配置、打开 bbolt 数据库、初始化 SAML IdP，监听 HTTP。
// 子命令 createsuperuser：交互式或通过 flag 创建第一个管理员账户。
package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"idaas/internal/auth"
	"idaas/internal/config"
	"idaas/internal/models"
	"idaas/internal/saml"
	"idaas/internal/store"
	"idaas/internal/webserver"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "createsuperuser" {
		createSuperUser(os.Args[2:])
		return
	}
	if err := runServer(); err != nil {
		fmt.Fprintln(os.Stderr, "启动失败：", err)
		os.Exit(1)
	}
}

// runServer 启动 HTTP 服务
func runServer() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("打开数据库失败：%w", err)
	}
	defer st.Close()

	authSvc := auth.New(st)

	idp, err := saml.New(saml.Config{
		EntityID:  cfg.SAMLEntityID,
		BaseURL:   cfg.SAMLBaseURL,
		ACSURL:    cfg.SAMLACSURL,
		CertPath:  cfg.SAMLCertPath,
		KeyPath:   cfg.SAMLKeyPath,
		IdpARN:    cfg.SAMLIdpARN,
		ValidMins: cfg.SAMLValidMins,
		OrgName:   cfg.SAMLOrgName,
		OrgDisp:   cfg.SAMLOrgDisp,
		OrgURL:    cfg.SAMLOrgURL,
		Contact:   cfg.SAMLContact,
	})
	if err != nil {
		return fmt.Errorf("初始化 SAML IdP 失败：%w", err)
	}

	srv, err := webserver.New(cfg, st, authSvc, idp)
	if err != nil {
		return err
	}

	if cfg.SAMLIdpARN == "" {
		fmt.Fprintln(os.Stderr, "警告：SAML_IDP_ARN 未配置；角色控制台登录将在阿里云侧创建 SAML IdP 并填入 ARN 后可用。")
	}
	fmt.Printf("iDaas 监听 %s（数据库 %s）\n", cfg.ListenAddr, cfg.DBPath)
	fmt.Printf("SAML metadata: %s\n", cfg.SAMLEntityID)

	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: srv.Handler()}
	return httpSrv.ListenAndServe()
}

// createSuperUser 创建管理员账户
func createSuperUser(args []string) {
	fs := flag.NewFlagSet("createsuperuser", flag.ExitOnError)
	username := fs.String("username", "", "管理员用户名")
	password := fs.String("password", "", "管理员密码（不指定则在终端交互输入）")
	email := fs.String("email", "", "邮箱")
	displayName := fs.String("display-name", "", "显示名")
	dbPath := fs.String("db", "", "覆盖数据库路径（默认读 DB_PATH 环境变量或 idaas.db）")
	fs.Parse(args)

	cfg, _ := config.Load()
	path := cfg.DBPath
	if *dbPath != "" {
		path = *dbPath
	}

	reader := bufio.NewReader(os.Stdin)
	if *username == "" {
		*username = prompt(reader, "用户名: ")
	}
	*username = strings.TrimSpace(*username)
	if *username == "" {
		fmt.Fprintln(os.Stderr, "错误：用户名不能为空")
		os.Exit(1)
	}
	if *password == "" {
		*password = prompt(reader, "密码: ")
	}
	if *password == "" {
		fmt.Fprintln(os.Stderr, "错误：密码不能为空")
		os.Exit(1)
	}
	if *email == "" {
		*email = prompt(reader, "邮箱（可选，回车跳过）: ")
	}
	if *displayName == "" {
		*displayName = prompt(reader, "显示名（可选，回车跳过）: ")
	}

	st, err := store.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "打开数据库失败：", err)
		os.Exit(1)
	}
	defer st.Close()

	if _, err := st.GetUserByUsername(*username); err == nil {
		fmt.Fprintf(os.Stderr, "错误：用户名 %s 已存在\n", *username)
		os.Exit(1)
	}
	hash, err := auth.HashPassword(*password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "密码哈希失败：", err)
		os.Exit(1)
	}
	u := &models.User{
		Username:     *username,
		PasswordHash: hash,
		IsAdmin:      true,
		IsActive:     true,
		Email:        strings.TrimSpace(*email),
		DisplayName:  strings.TrimSpace(*displayName),
	}
	if err := st.CreateUser(u); err != nil {
		fmt.Fprintln(os.Stderr, "创建用户失败：", err)
		os.Exit(1)
	}
	fmt.Printf("已创建管理员账户 %s（ID=%d）于数据库 %s\n", u.Username, u.ID, path)
}

// prompt 在终端打印标签并读取一行输入
func prompt(reader *bufio.Reader, label string) string {
	fmt.Print(label)
	line, _ := reader.ReadString('\n')
	return strings.TrimRight(line, "\r\n")
}
