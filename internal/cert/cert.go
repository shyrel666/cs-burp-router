package cert

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultFetchTimeout 是从上游 Burp 代理拉取 CA 证书的默认超时时间。
	DefaultFetchTimeout = 3 * time.Second
	maxCertBodyBytes    = 256 * 1024
)

var (
	// ErrInvalidFingerprint indicates a malformed SHA-256 confirmation.
	ErrInvalidFingerprint = errors.New("证书 SHA-256 指纹格式无效")
	// ErrFingerprintMismatch indicates the downloaded CA differs from the confirmed one.
	ErrFingerprintMismatch = errors.New("当前 Burp 证书的 SHA-256 指纹已变化，请重新核对")
	// ErrTrustNotConfirmed means the certificate write succeeded but effective trust could not be verified.
	ErrTrustNotConfirmed = errors.New("已写入证书，但未能确认系统信任该证书")
	// ErrCleanupIncomplete means one or more matching roots remain trusted after cleanup.
	ErrCleanupIncomplete = errors.New("仍有匹配的根证书受信任，清理未完成")
)

// DialFunc 定义底层网络连接拨号函数签名（便于单元测试注入模拟 Burp 服务）。
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// ParsedCA 保存从 Burp 拉取并通过 X.509 校验的根证书信息。
type ParsedCA struct {
	RawDER            []byte
	CommonName        string
	Subject           string
	FingerprintSHA1   string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
}

// Store 抽象系统受信任根证书存储区的查询、安装与卸载能力。
type Store interface {
	Inspect(fingerprintSHA1 string) (installed bool, scopes []string, portSwiggerCount int, err error)
	InstallRootCA(rawDER []byte, preferMachine bool) (scope string, err error)
	RemoveBurpCAs(fingerprintSHA1 string, isAdmin bool) (removed int, warning string, err error)
}

// Status 表示当前 Burp 根证书的在线可达性与本机安装状态快照。
type Status struct {
	BurpAddr          string   `json:"burpAddr"`
	BurpReachable     bool     `json:"burpReachable"`
	ReachError        string   `json:"reachError,omitempty"`
	CommonName        string   `json:"commonName,omitempty"`
	Subject           string   `json:"subject,omitempty"`
	Fingerprint       string   `json:"fingerprint,omitempty"`
	FingerprintSHA256 string   `json:"fingerprintSHA256,omitempty"`
	NotAfter          string   `json:"notAfter,omitempty"`
	Installed         bool     `json:"installed"`
	InstalledScope    string   `json:"installedScope,omitempty"`
	Scopes            []string `json:"scopes,omitempty"`
	LegacyCount       int      `json:"legacyCount"`
	StoreError        string   `json:"storeError,omitempty"`
	IsAdmin           bool     `json:"isAdmin"`
}

// ActionResponse 表示执行证书安装或卸载操作后的响应结果。
type ActionResponse struct {
	Status
	ActionScope  string `json:"actionScope,omitempty"`
	RemovedCount int    `json:"removedCount,omitempty"`
	Warning      string `json:"warning,omitempty"`
}

// ManagerConfig 定义证书管理器配置。
type ManagerConfig struct {
	Store        Store
	DialContext  DialFunc
	AdminChecker func() bool
	FetchTimeout time.Duration
}

// Manager 负责从 Burp 拉取根证书并管理本机受信任根证书存储。
type Manager struct {
	actionMu     sync.Mutex
	store        Store
	dialContext  DialFunc
	adminChecker func() bool
	fetchTimeout time.Duration
}

// NewManager 创建并发安全的 Burp 证书管理器。
func NewManager(cfg ManagerConfig) *Manager {
	st := cfg.Store
	if st == nil {
		st = NewSystemStore()
	}
	ft := cfg.FetchTimeout
	if ft <= 0 {
		ft = DefaultFetchTimeout
	}
	dialFn := cfg.DialContext
	if dialFn == nil {
		dialer := &net.Dialer{Timeout: ft}
		dialFn = dialer.DialContext
	}
	adminFn := cfg.AdminChecker
	if adminFn == nil {
		adminFn = func() bool { return false }
	}
	return &Manager{
		store:        st,
		dialContext:  dialFn,
		adminChecker: adminFn,
		fetchTimeout: ft,
	}
}

// CheckStatus 连接给定 burpAddr 拉取证书指纹并对比本机受信任根证书库状态。
func (m *Manager) CheckStatus(ctx context.Context, burpAddr string) Status {
	ca, fetchErr := m.FetchCA(ctx, burpAddr)
	return m.statusForCA(burpAddr, ca, fetchErr, m.adminChecker())
}

func (m *Manager) statusForCA(burpAddr string, ca *ParsedCA, fetchErr error, isAdmin bool) Status {
	out := Status{
		BurpAddr: burpAddr,
		IsAdmin:  isAdmin,
		Scopes:   []string{},
	}

	fp := ""
	if ca != nil {
		out.BurpReachable = true
		out.CommonName = ca.CommonName
		out.Subject = ca.Subject
		out.Fingerprint = ca.FingerprintSHA1
		out.FingerprintSHA256 = ca.FingerprintSHA256
		out.NotAfter = ca.NotAfter.Format("2006-01-02")
		fp = ca.FingerprintSHA1
	} else if fetchErr != nil {
		out.ReachError = fetchErr.Error()
	}

	installed, scopes, legacyCount, err := m.store.Inspect(fp)
	if err != nil {
		out.StoreError = err.Error()
	}
	out.Installed = installed && out.BurpReachable
	if len(scopes) > 0 {
		out.Scopes = scopes
		out.InstalledScope = strings.Join(scopes, ", ")
	}
	out.LegacyCount = legacyCount
	return out
}

// Install 从给定 burpAddr 拉取最新 CA 证书并写入本机受信任根证书存储区。
// 若当前为管理员权限，优先写入 LocalMachine\Root，否则写入 CurrentUser\Root。
func (m *Manager) Install(ctx context.Context, burpAddr string) (ActionResponse, error) {
	return m.install(ctx, burpAddr, "")
}

// InstallVerified only installs the exact certificate confirmed by its SHA-256 fingerprint.
func (m *Manager) InstallVerified(ctx context.Context, burpAddr, fingerprintSHA256 string) (ActionResponse, error) {
	fingerprintSHA256 = strings.ToUpper(strings.TrimSpace(fingerprintSHA256))
	if _, err := hex.DecodeString(fingerprintSHA256); len(fingerprintSHA256) != 2*sha256.Size || err != nil {
		return ActionResponse{}, ErrInvalidFingerprint
	}
	return m.install(ctx, burpAddr, fingerprintSHA256)
}

func (m *Manager) install(ctx context.Context, burpAddr, fingerprintSHA256 string) (ActionResponse, error) {
	ca, err := m.FetchCA(ctx, burpAddr)
	if err != nil {
		return ActionResponse{}, fmt.Errorf("无法从 Burp (%s) 获取证书: %w", burpAddr, err)
	}
	if fingerprintSHA256 != "" && ca.FingerprintSHA256 != fingerprintSHA256 {
		return ActionResponse{}, ErrFingerprintMismatch
	}

	m.actionMu.Lock()
	defer m.actionMu.Unlock()
	if err := ctx.Err(); err != nil {
		return ActionResponse{}, err
	}
	isAdmin := m.adminChecker()
	scope, err := m.store.InstallRootCA(ca.RawDER, isAdmin)
	if err != nil {
		return ActionResponse{}, fmt.Errorf("写入系统受信任根证书库失败: %w", err)
	}

	res := ActionResponse{
		Status:      m.statusForCA(burpAddr, ca, nil, isAdmin),
		ActionScope: scope,
	}
	if !res.Installed {
		if res.StoreError != "" {
			return res, fmt.Errorf("%w: %s", ErrTrustNotConfirmed, res.StoreError)
		}
		return res, ErrTrustNotConfirmed
	}
	return res, nil
}

// Uninstall 清理本机受信任根证书库中匹配的当前 Burp 证书及所有 PortSwigger CA 根证书（便于现场撤场还原）。
func (m *Manager) Uninstall(ctx context.Context, burpAddr string) (ActionResponse, error) {
	ca, fetchErr := m.FetchCA(ctx, burpAddr)
	fp := ""
	if ca != nil {
		fp = ca.FingerprintSHA1
	}

	m.actionMu.Lock()
	defer m.actionMu.Unlock()
	if err := ctx.Err(); err != nil {
		return ActionResponse{}, err
	}
	isAdmin := m.adminChecker()
	removed, warning, err := m.store.RemoveBurpCAs(fp, isAdmin)
	res := ActionResponse{
		Status:       m.statusForCA(burpAddr, ca, fetchErr, isAdmin),
		RemovedCount: removed,
		Warning:      warning,
	}
	if errors.Is(err, ErrCleanupIncomplete) {
		return res, err
	}
	if err != nil {
		return res, fmt.Errorf("清理系统根证书失败: %w", err)
	}
	return res, nil
}

// FetchCA 通过 HTTP 从指定 Burp 监听地址下载并解析校验 X.509 CA 根证书。
func (m *Manager) FetchCA(ctx context.Context, burpAddr string) (*ParsedCA, error) {
	addr := strings.TrimSpace(burpAddr)
	if addr == "" {
		return nil, errors.New("Burp 地址为空")
	}

	fetchCtx, cancel := context.WithTimeout(ctx, m.fetchTimeout)
	defer cancel()

	// 兼容开启或未开启隐形代理的 Burp Listener 以及标准 HTTP 服务
	rawBody, err := m.tryDownloadCert(fetchCtx, addr, "/cert")
	if err != nil {
		if altBody, altErr := m.tryDownloadCert(fetchCtx, addr, "http://burp/cert"); altErr == nil {
			rawBody = altBody
			err = nil
		}
	}
	if err != nil {
		return nil, err
	}

	return ParseAndValidateCA(rawBody)
}

func (m *Manager) tryDownloadCert(ctx context.Context, burpAddr, requestURI string) ([]byte, error) {
	conn, err := m.dialContext(ctx, "tcp", burpAddr)
	if err != nil {
		return nil, fmt.Errorf("连接 %s 失败 (%v)", burpAddr, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(m.fetchTimeout))
	}

	reqRaw := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: burp\r\nUser-Agent: CS-Burp-Router/1.0\r\nConnection: close\r\n\r\n",
		requestURI,
	)
	if _, err := io.WriteString(conn, reqRaw); err != nil {
		return nil, fmt.Errorf("发送证书拉取请求失败: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, fmt.Errorf("读取 Burp 响应失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Burp 返回状态码 %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCertBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("读取证书内容失败: %w", err)
	}
	if len(body) == 0 {
		return nil, errors.New("Burp 返回了空的证书响应")
	}
	return body, nil
}

// ParseAndValidateCA 解析 DER 或 PEM 编码的字节流并验证其为合法的 X.509 CA 根证书。
func ParseAndValidateCA(raw []byte) (*ParsedCA, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("证书内容为空")
	}

	der := raw
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		block, _ := pem.Decode(trimmed)
		if block == nil || len(block.Bytes) == 0 {
			return nil, errors.New("无效的 PEM 证书格式")
		}
		der = block.Bytes
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("返回内容不是有效的 X.509 证书（请确认端口对应的是 Burp Proxy Listener）: %w", err)
	}
	if !cert.IsCA && (cert.KeyUsage&x509.KeyUsageCertSign) == 0 {
		return nil, errors.New("目标端点返回的证书不是 CA 根证书")
	}

	sum := sha1.Sum(cert.Raw)
	sum256 := sha256.Sum256(cert.Raw)
	cn := strings.TrimSpace(cert.Subject.CommonName)
	if cn == "" {
		cn = cert.Subject.String()
	}

	return &ParsedCA{
		RawDER:            append([]byte(nil), cert.Raw...),
		CommonName:        cn,
		Subject:           cert.Subject.String(),
		FingerprintSHA1:   strings.ToUpper(hex.EncodeToString(sum[:])),
		FingerprintSHA256: strings.ToUpper(hex.EncodeToString(sum256[:])),
		NotBefore:         cert.NotBefore,
		NotAfter:          cert.NotAfter,
	}, nil
}

func isPortSwiggerCert(c *x509.Certificate) bool {
	if c == nil {
		return false
	}
	fields := []string{
		c.Subject.CommonName,
		c.Issuer.CommonName,
		strings.Join(c.Subject.Organization, " "),
		strings.Join(c.Subject.OrganizationalUnit, " "),
	}
	joined := strings.ToLower(strings.Join(fields, " "))
	return strings.Contains(joined, "portswigger")
}
