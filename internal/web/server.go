package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"cs-burp-router/internal/bridge"
	"cs-burp-router/internal/cert"
	"cs-burp-router/internal/detector"
	"cs-burp-router/internal/forwarder"
	"cs-burp-router/internal/socks5"
	"cs-burp-router/internal/tracker"
)

// DefaultListenAddr 是本地实时连接看板 Web 服务默认监听地址。
const DefaultListenAddr = "127.0.0.1:18080"

const streamWriteTimeout = 3 * time.Second

//go:embed static/*
var embeddedAssets embed.FS

// ProcessListFunc 定义枚举本机运行中进程名列表的函数签名。
type ProcessListFunc func(ctx context.Context) ([]string, error)

// ProcessDetailListFunc 定义枚举本机运行中进程详情列表（含应用名与窗口标题）的函数签名。
type ProcessDetailListFunc func(ctx context.Context) ([]bridge.ProcessInfo, error)

// Config 定义内嵌 Web 看板服务配置。
type Config struct {
	ListenAddr          string
	Tracker             *tracker.Tracker
	Detector            *detector.Detector
	Forwarder           *forwarder.Forwarder
	SocksServer         *socks5.Server
	Bridge              *bridge.Manager
	Cert                *cert.Manager
	ProcessLister       ProcessListFunc
	ProcessDetailLister ProcessDetailListFunc
	Logger              *log.Logger
}

// ConnectionsResponse 是 GET /api/connections 与 SSE 推送的响应载荷。
type ConnectionsResponse struct {
	Connections []tracker.Record `json:"connections"`
	Total       int              `json:"total"`
	Capacity    int              `json:"capacity"`
}

// ConfigResponse 是 GET/POST /api/config 返回的完整运行时配置快照。
type ConfigResponse struct {
	SocksListenAddr string   `json:"socksListenAddr"`
	WebListenAddr   string   `json:"webListenAddr"`
	BurpAddr        string   `json:"burpAddr"`
	DirectPorts     []uint16 `json:"directPorts"`
	BypassAll       bool     `json:"bypassAll"`
}

// ConfigUpdateRequest 是 POST /api/config 接收的热更新参数（支持部分字段或全量更新）。
type ConfigUpdateRequest struct {
	BurpAddr    *string `json:"burpAddr"`
	DirectPorts *[]int  `json:"directPorts"`
	BypassAll   *bool   `json:"bypassAll"`
}

// BridgeProcessesResponse 是 GET /api/bridge/processes 的响应载荷。
type BridgeProcessesResponse struct {
	Processes []string             `json:"processes"`
	Items     []bridge.ProcessInfo `json:"items"`
}

// BridgeStartRequest 是 POST /api/bridge/start 的请求载荷。
type BridgeStartRequest struct {
	Processes        []string `json:"processes"`
	TargetDomains    *string  `json:"target_domains"`
	TargetDomainsAlt *string  `json:"targetDomains"`
}

// CertInstallRequest 是 POST /api/cert/install 的可选请求载荷。
type CertInstallRequest struct {
	BurpAddr          string `json:"burpAddr"`
	FingerprintSHA256 string `json:"fingerprintSHA256"`
}

type certActionErrorResponse struct {
	cert.ActionResponse
	Error string `json:"error"`
}

// Server 提供内嵌单页看板静态资源与运行时管理 REST/SSE 接口。
type Server struct {
	listenAddr          string
	tracker             *tracker.Tracker
	detector            *detector.Detector
	forwarder           *forwarder.Forwarder
	socksServer         *socks5.Server
	bridge              *bridge.Manager
	cert                *cert.Manager
	processLister       ProcessListFunc
	processDetailLister ProcessDetailListFunc
	logger              *log.Logger

	configMu            sync.RWMutex
	standaloneBypassAll bool
	sessionToken        string

	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.RWMutex
	actualAddr string
	httpServer *http.Server
	handler    http.Handler
}

// NewServer 根据配置创建 Web 看板服务端。
func NewServer(cfg Config) *Server {
	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = DefaultListenAddr
	}
	tr := cfg.Tracker
	if tr == nil {
		tr = tracker.New(tracker.DefaultCapacity)
	}
	det := cfg.Detector
	if det == nil && cfg.SocksServer != nil {
		det = cfg.SocksServer.Detector()
	}
	if det == nil {
		det = detector.NewDefault()
	}
	fwd := cfg.Forwarder
	if fwd == nil && cfg.SocksServer != nil {
		fwd = cfg.SocksServer.Forwarder()
	}
	if fwd == nil {
		fwd = forwarder.NewDefault()
	}

	socksAddr := socks5.DefaultListenAddr
	if cfg.SocksServer != nil {
		socksAddr = cfg.SocksServer.Addr()
	}
	br := cfg.Bridge
	if br == nil {
		br = bridge.NewManager(bridge.ManagerConfig{
			SocksAddr: socksAddr,
			Logger:    cfg.Logger,
		})
	}
	certMgr := cfg.Cert
	if certMgr == nil {
		certMgr = cert.NewManager(cert.ManagerConfig{
			AdminChecker: func() bool {
				return br.Status().IsAdmin
			},
			FetchTimeout: 2 * time.Second,
		})
	}
	procLister := cfg.ProcessLister
	detailLister := cfg.ProcessDetailLister
	if detailLister == nil && procLister == nil {
		detailLister = bridge.ListRunningProcessDetails
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{
		listenAddr:          listenAddr,
		tracker:             tr,
		detector:            det,
		forwarder:           fwd,
		socksServer:         cfg.SocksServer,
		bridge:              br,
		cert:                certMgr,
		processLister:       procLister,
		processDetailLister: detailLister,
		logger:              cfg.Logger,
		sessionToken:        rand.Text(),
		ctx:                 ctx,
		cancel:              cancel,
	}

	mux := http.NewServeMux()
	staticSub, err := fs.Sub(embeddedAssets, "static")
	if err != nil {
		panic("failed to load embedded static assets: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(staticSub))

	mux.HandleFunc("/api/connections", s.handleConnections)
	mux.HandleFunc("/api/connections/stream", s.handleConnectionsStream)
	mux.HandleFunc("/api/connections/clear", s.handleConnectionsClear)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/bridge/status", s.handleBridgeStatus)
	mux.HandleFunc("/api/bridge/processes", s.handleBridgeProcesses)
	mux.HandleFunc("/api/bridge/start", s.handleBridgeStart)
	mux.HandleFunc("/api/bridge/stop", s.handleBridgeStop)
	mux.HandleFunc("/api/cert/status", s.handleCertStatus)
	mux.HandleFunc("/api/cert/install", s.handleCertInstall)
	mux.HandleFunc("/api/cert/uninstall", s.handleCertUninstall)
	mux.HandleFunc("/api/cert/download", s.handleCertDownload)
	mux.HandleFunc("/favicon.ico", s.handleFavicon)
	mux.Handle("/static/", http.StripPrefix("/static/", fileServer))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		data, err := embeddedAssets.ReadFile("static/index.html")
		if err != nil {
			writeErrorJSON(w, http.StatusInternalServerError, "index.html missing")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(data)
	})

	s.handler = s.authorizeAPI(mux)
	s.httpServer = &http.Server{
		Addr:              listenAddr,
		Handler:           s.handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return s
}

// Handler 返回内部 HTTP 路由处理器（便于单元测试直接调用）。
func (s *Server) Handler() http.Handler {
	return s.handler
}

// LaunchURL returns the local dashboard URL, with its access token kept in the
// fragment so browsers do not send it in request URLs.
func (s *Server) LaunchURL() string {
	u := url.URL{Scheme: "http", Host: s.Addr(), Path: "/", Fragment: "session=" + s.sessionToken}
	return u.String()
}

func (s *Server) authorizeAPI(next http.Handler) http.Handler {
	handler := http.NewCrossOriginProtection().Handler(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
			if !matchesDashboardHost(r.Host, s.Addr()) {
				writeErrorJSON(w, http.StatusForbidden, "invalid dashboard host")
				return
			}
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(s.sessionToken)) != 1 {
				writeErrorJSON(w, http.StatusUnauthorized, "dashboard session is required")
				return
			}
		}
		handler.ServeHTTP(w, r)
	})
}

func matchesDashboardHost(requestHost, dashboardAddr string) bool {
	if strings.EqualFold(requestHost, dashboardAddr) {
		return true
	}
	host, port, err := net.SplitHostPort(dashboardAddr)
	if err != nil || port != "80" {
		return false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return strings.EqualFold(requestHost, host)
}

// Addr 返回 Web 服务端实际绑定的监听地址。
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.actualAddr != "" {
		return s.actualAddr
	}
	return s.listenAddr
}

// ListenAndServe 在配置的 ListenAddr 上启动 HTTP 服务。
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("web listen %s: %w", s.listenAddr, err)
	}
	return s.Serve(ln)
}

// Serve 使用给定的 net.Listener 运行 HTTP 服务；正常关闭时返回 nil。
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.actualAddr = ln.Addr().String()
	httpSrv := s.httpServer
	s.mu.Unlock()

	err := httpSrv.Serve(ln)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("web serve: %w", err)
	}
	return nil
}

// Shutdown 优雅关闭 Web 服务（先通知所有 SSE 长连接退出，再关闭 HTTP Server）。
func (s *Server) Shutdown(ctx context.Context) error {
	s.cancel()
	s.mu.RLock()
	httpSrv := s.httpServer
	s.mu.RUnlock()
	return httpSrv.Shutdown(ctx)
}

// Close 立即停止 Web 服务。
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.Shutdown(ctx)
}

func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	data, err := embeddedAssets.ReadFile("static/favicon.ico")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(data)
	}
}

func (s *Server) handleConnections(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "only GET is allowed")
		return
	}
	list := s.tracker.List()
	if list == nil {
		list = []tracker.Record{}
	}
	writeJSON(w, http.StatusOK, ConnectionsResponse{
		Connections: list,
		Total:       len(list),
		Capacity:    s.tracker.Capacity(),
	})
}

func (s *Server) handleConnectionsStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "only GET is allowed")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	notifyCh, unsubscribe := s.tracker.Subscribe()
	defer unsubscribe()

	controller := http.NewResponseController(w)
	writeEvent := func(event string) error {
		if err := controller.SetWriteDeadline(time.Now().Add(streamWriteTimeout)); err != nil {
			return err
		}
		if _, err := io.WriteString(w, event); err != nil {
			return err
		}
		if err := controller.Flush(); err != nil {
			return err
		}
		return controller.SetWriteDeadline(time.Time{})
	}

	sendSnapshot := func() error {
		list := s.tracker.List()
		if list == nil {
			list = []tracker.Record{}
		}
		payload, err := json.Marshal(ConnectionsResponse{
			Connections: list,
			Total:       len(list),
			Capacity:    s.tracker.Capacity(),
		})
		if err != nil {
			return err
		}
		return writeEvent("event: connections\ndata: " + string(payload) + "\n\n")
	}

	if err := sendSnapshot(); err != nil {
		return
	}

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.ctx.Done():
			return
		case <-notifyCh:
			if err := sendSnapshot(); err != nil {
				return
			}
		case <-heartbeat.C:
			if err := writeEvent(": keepalive\n\n"); err != nil {
				return
			}
		}
	}
}

func (s *Server) handleConnectionsClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "only POST is allowed")
		return
	}
	s.tracker.Clear()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.configMu.RLock()
		cfg := s.snapshotConfig()
		s.configMu.RUnlock()
		writeJSON(w, http.StatusOK, cfg)

	case http.MethodPost:
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeErrorJSON(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		var req ConfigUpdateRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeErrorJSON(w, http.StatusBadRequest, "invalid JSON payload: "+err.Error())
			return
		}

		var (
			hasBurp     bool
			cleanBurp   string
			hasPorts    bool
			cleanPorts  []uint16
			hasBypass   bool
			cleanBypass bool
		)

		if req.BurpAddr != nil {
			addr, err := validateHostPort(*req.BurpAddr)
			if err != nil {
				writeErrorJSON(w, http.StatusBadRequest, "invalid burpAddr: "+err.Error())
				return
			}
			socksAddr := s.socksListenAddr()
			if socksAddr != "" && sameLocalEndpoint(addr, socksAddr) {
				writeErrorJSON(w, http.StatusBadRequest, "burpAddr cannot be identical to SOCKS5 listen address")
				return
			}
			if sameLocalEndpoint(addr, s.Addr()) {
				writeErrorJSON(w, http.StatusBadRequest, "burpAddr cannot be identical to Web UI listen address")
				return
			}
			hasBurp = true
			cleanBurp = addr
		}

		if req.DirectPorts != nil {
			seen := make(map[uint16]struct{}, len(*req.DirectPorts))
			cleanPorts = make([]uint16, 0, len(*req.DirectPorts))
			for _, p := range *req.DirectPorts {
				if p < 1 || p > 65535 {
					writeErrorJSON(w, http.StatusBadRequest, fmt.Sprintf("invalid port %d: must be between 1 and 65535", p))
					return
				}
				up := uint16(p)
				if _, exists := seen[up]; !exists {
					seen[up] = struct{}{}
					cleanPorts = append(cleanPorts, up)
				}
			}
			slices.Sort(cleanPorts)
			hasPorts = true
		}

		if req.BypassAll != nil {
			hasBypass = true
			cleanBypass = *req.BypassAll
		}

		s.configMu.Lock()
		var cfg ConfigResponse
		if s.socksServer != nil {
			var update socks5.RoutingUpdate
			if hasBurp {
				update.BurpAddr = &cleanBurp
			}
			if hasPorts {
				update.DirectPorts = &cleanPorts
			}
			if hasBypass {
				update.BypassAll = &cleanBypass
			}
			updated := s.socksServer.UpdateRoutingConfig(update)
			cfg = s.configResponse(updated.BurpAddr, updated.DirectPorts, updated.BypassAll)
		} else {
			if hasBurp {
				s.forwarder.SetBurpAddr(cleanBurp)
			}
			if hasPorts {
				s.detector.SetDirectPorts(cleanPorts)
			}
			if hasBypass {
				s.standaloneBypassAll = cleanBypass
			}
			cfg = s.snapshotConfig()
		}
		s.configMu.Unlock()
		if s.logger != nil {
			s.logger.Printf(
				"CONFIG UPDATED | burp=%s | direct_ports=%v | bypass_all=%v",
				cfg.BurpAddr,
				cfg.DirectPorts,
				cfg.BypassAll,
			)
		}

		writeJSON(w, http.StatusOK, cfg)

	default:
		writeErrorJSON(w, http.StatusMethodNotAllowed, "only GET and POST are allowed")
	}
}

func (s *Server) handleBridgeStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "only GET is allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.bridge.Status())
}

func (s *Server) handleBridgeProcesses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "only GET is allowed")
		return
	}

	if s.processDetailLister != nil {
		items, err := s.processDetailLister(r.Context())
		if err != nil {
			writeErrorJSON(w, http.StatusInternalServerError, "list running processes failed: "+err.Error())
			return
		}
		if items == nil {
			items = []bridge.ProcessInfo{}
		}
		procs := make([]string, 0, len(items))
		for _, item := range items {
			procs = append(procs, item.Name)
		}
		writeJSON(w, http.StatusOK, BridgeProcessesResponse{
			Processes: procs,
			Items:     items,
		})
		return
	}

	procs, err := s.processLister(r.Context())
	if err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, "list running processes failed: "+err.Error())
		return
	}
	if procs == nil {
		procs = []string{}
	}
	items := make([]bridge.ProcessInfo, 0, len(procs))
	for _, p := range procs {
		items = append(items, bridge.ProcessInfo{Name: p})
	}
	writeJSON(w, http.StatusOK, BridgeProcessesResponse{
		Processes: procs,
		Items:     items,
	})
}

func (s *Server) handleBridgeStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "only POST is allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	var req BridgeStartRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "invalid JSON payload: "+err.Error())
		return
	}

	cleanedProcs, err := bridge.NormalizeProcessList(req.Processes)
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	targetDomains := req.TargetDomains
	if targetDomains == nil && req.TargetDomainsAlt != nil {
		targetDomains = req.TargetDomainsAlt
	}

	if err := s.bridge.RestartWithOptions(bridge.StartOptions{
		Processes:     cleanedProcs,
		TargetDomains: targetDomains,
	}); err != nil {
		status := http.StatusInternalServerError
		message := err.Error()
		switch {
		case errors.Is(err, bridge.ErrManagerClosed):
			status = http.StatusServiceUnavailable
		case errors.Is(err, bridge.ErrAdminRequired):
			status = http.StatusForbidden
			message = "进程接管需要管理员权限。请以管理员身份重新运行程序，或将客户端直接配置为使用本地 SOCKS5 代理。"
		}
		writeErrorJSON(w, status, message)
		return
	}

	writeJSON(w, http.StatusOK, s.bridge.Status())
}

func (s *Server) handleBridgeStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "only POST is allowed")
		return
	}
	if err := s.bridge.Stop(); err != nil {
		writeErrorJSON(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.bridge.Status())
}

func (s *Server) handleCertStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "only GET is allowed")
		return
	}
	writeJSON(w, http.StatusOK, s.cert.CheckStatus(r.Context(), s.burpAddr()))
}

func (s *Server) handleCertInstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "only POST is allowed")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	var req CertInstallRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeErrorJSON(w, http.StatusBadRequest, "invalid JSON payload: "+err.Error())
		return
	}
	s.configMu.RLock()
	burpAddr := s.burpAddr()
	s.configMu.RUnlock()
	if req.BurpAddr != burpAddr {
		writeErrorJSON(w, http.StatusConflict, "Burp 地址已变更，请重新核对证书")
		return
	}
	// The confirmed address and fingerprint are fixed for this operation, even
	// if an operator updates the routing configuration during the fetch.
	res, err := s.cert.InstallVerified(r.Context(), burpAddr, req.FingerprintSHA256)
	if err != nil {
		status := http.StatusBadGateway
		switch {
		case errors.Is(err, cert.ErrInvalidFingerprint):
			status = http.StatusBadRequest
		case errors.Is(err, cert.ErrFingerprintMismatch):
			status = http.StatusConflict
		case errors.Is(err, cert.ErrTrustNotConfirmed):
			if s.logger != nil {
				s.logger.Printf("BURP CA TRUST UNCONFIRMED | burp=%s | scope=%s | error=%q", burpAddr, res.ActionScope, err)
			}
			writeJSON(w, http.StatusConflict, certActionErrorResponse{ActionResponse: res, Error: err.Error()})
			return
		}
		writeErrorJSON(w, status, err.Error())
		return
	}
	if s.logger != nil {
		s.logger.Printf(
			"BURP CA INSTALLED | burp=%s | subject=%q | sha1=%s | scope=%s",
			burpAddr,
			res.CommonName,
			res.Fingerprint,
			res.ActionScope,
		)
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleCertUninstall(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "only POST is allowed")
		return
	}
	burpAddr := s.burpAddr()
	res, err := s.cert.Uninstall(r.Context(), burpAddr)
	if err != nil {
		status := http.StatusInternalServerError
		outcome := "FAILED"
		if errors.Is(err, cert.ErrCleanupIncomplete) {
			status = http.StatusConflict
			outcome = "INCOMPLETE"
		}
		if s.logger != nil {
			s.logger.Printf("BURP CA CLEANUP %s | removed=%d | warning=%q | error=%q", outcome, res.RemovedCount, res.Warning, err)
		}
		writeJSON(w, status, certActionErrorResponse{ActionResponse: res, Error: err.Error()})
		return
	}
	if s.logger != nil {
		if res.Warning != "" {
			s.logger.Printf("BURP CA CLEANUP INCOMPLETE | removed=%d | warning=%q", res.RemovedCount, res.Warning)
		} else {
			s.logger.Printf("BURP CA UNINSTALLED | removed=%d", res.RemovedCount)
		}
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleCertDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErrorJSON(w, http.StatusMethodNotAllowed, "only GET is allowed")
		return
	}
	burpAddr := s.burpAddr()
	ca, err := s.cert.FetchCA(r.Context(), burpAddr)
	if err != nil {
		writeErrorJSON(w, http.StatusBadGateway, "无法从 Burp 拉取证书: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="burp-cacert.der"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(ca.RawDER)
}

func (s *Server) snapshotConfig() ConfigResponse {
	if s.socksServer != nil {
		cfg := s.socksServer.RoutingConfig()
		return s.configResponse(cfg.BurpAddr, cfg.DirectPorts, cfg.BypassAll)
	}
	return s.configResponse(s.forwarder.BurpAddr(), s.detector.DirectPorts(), s.standaloneBypassAll)
}

func (s *Server) configResponse(burpAddr string, ports []uint16, bypassAll bool) ConfigResponse {
	if ports == nil {
		ports = []uint16{}
	}
	return ConfigResponse{
		SocksListenAddr: s.socksListenAddr(),
		WebListenAddr:   s.Addr(),
		BurpAddr:        burpAddr,
		DirectPorts:     ports,
		BypassAll:       bypassAll,
	}
}

func (s *Server) socksListenAddr() string {
	if s.socksServer != nil {
		return s.socksServer.Addr()
	}
	return socks5.DefaultListenAddr
}

func (s *Server) burpAddr() string {
	if s.socksServer != nil {
		return s.socksServer.RoutingConfig().BurpAddr
	}
	return s.forwarder.BurpAddr()
}

func validateHostPort(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("address cannot be empty")
	}
	host, portStr, err := net.SplitHostPort(trimmed)
	if err != nil {
		return "", err
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("host cannot be empty")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", errors.New("port must be between 1 and 65535")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func sameLocalEndpoint(addrA, addrB string) bool {
	hostA, portA, errA := net.SplitHostPort(addrA)
	hostB, portB, errB := net.SplitHostPort(addrB)
	if errA != nil || errB != nil || portA != portB {
		return false
	}
	if strings.EqualFold(hostA, hostB) {
		return true
	}
	return isLocalHost(hostA) && isLocalHost(hostB)
}

func isLocalHost(h string) bool {
	if h == "" || strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErrorJSON(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
