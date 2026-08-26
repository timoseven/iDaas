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
	"os/exec"
	"strings"
	"syscall"

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
	fs := flag.NewFlagSet("idaas", flag.ExitOnError)
	envFile := fs.String("env", "", "加载 .env 风格文件到进程环境变量（已存在的环境变量优先，不被覆盖）")
	daemon := fs.Bool("daemon", false, "后台 daemon 方式运行：脱离终端，输出写入 -log 指定文件")
	logFile := fs.String("log", "idaas.log", "daemon 模式下的日志文件路径")
	fs.Parse(os.Args[1:])

	if *daemon {
		return startDaemon(os.Args[0], *envFile, *logFile)
	}

	if *envFile != "" {
		if err := config.LoadEnvFile(*envFile); err != nil {
			return fmt.Errorf("加载环境变量文件 %q 失败：%w", *envFile, err)
		}
	}

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
		CertPath:  cfg.SAMLCertPath,
		KeyPath:   cfg.SAMLKeyPath,
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

	fmt.Printf("iDaas 监听 %s（数据库 %s）\n", cfg.ListenAddr, cfg.DBPath)
	fmt.Printf("SAML metadata: %s\n", cfg.SAMLEntityID)

	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: srv.Handler()}
	return httpSrv.ListenAndServe()
}

// startDaemon 以 daemon 方式重新拉起自身：子进程脱离终端（setsid），stdin 取自
// /dev/null，stdout/stderr 写入日志文件；父进程打印 PID 后退出，子进程由 init 接管。
func startDaemon(exe, envFile, logFile string) error {
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("打开日志文件 %q 失败：%w", logFile, err)
	}
	defer f.Close()

	args := []string{}
	if envFile != "" {
		args = append(args, "-env", envFile)
	}
	cmd := exec.Command(exe, args...)
	cmd.Stdin = nil
	cmd.Stdout = f
	cmd.Stderr = f
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 daemon 失败：%w", err)
	}
	fmt.Printf("iDaas 已在后台运行（PID=%d），日志：%s\n", cmd.Process.Pid, logFile)
	return nil
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
