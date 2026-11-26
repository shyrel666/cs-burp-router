package web

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cs-burp-router/internal/bridge"
	"cs-burp-router/internal/cert"
	"cs-burp-router/internal/detector"
	"cs-burp-router/internal/forwarder"
	"cs-burp-router/internal/socks5"
	"cs-burp-router/internal/tracker"
)

type dashboardTransport struct {
	host  string
	token string
}

func (tr dashboardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == tr.host {
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", "Bearer "+tr.token)
	}
	return http.DefaultTransport.RoundTrip(req)
}

func dashboardClient(t *testing.T, srv *Server, baseURL string) *http.Client {
	t.Helper()
	launch, err := url.Parse(srv.LaunchURL())
	if err != nil {
		t.Fatal(err)
	}
	values, err := url.ParseQuery(launch.Fragment)
	if err != nil || values.Get("session") == "" {
		t.Fatal("dashboard launch URL has no session token")
	}
	return &http.Client{Transport: dashboardTransport{
		host:  strings.TrimPrefix(baseURL, "http://"),
		token: values.Get("session"),
	}}
}

func startDashboard(t *testing.T, srv *Server) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "http://" + ln.Addr().String()
}

func TestDashboardAuthorization(t *testing.T) {
	srv := NewServer(Config{})
	baseURL := startDashboard(t, srv)
	resp, err := http.Get(baseURL + "/api/config")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API status = %d, want 401", resp.StatusCode)
	}
	client := dashboardClient(t, srv, baseURL)
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/config", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "localhost"
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("invalid Host API status = %d, want 403", resp.StatusCode)
	}
	resp, err = client.Get(baseURL + "/api/config")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated API status = %d, want 200", resp.StatusCode)
	}

	req, err = http.NewRequest(http.MethodPost, baseURL+"/api/config", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "http://localhost")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin API write status = %d, want 403", resp.StatusCode)
	}
}

func TestOfflineEmbeddedAssetsHaveNoExternalLinks(t *testing.T) {
	srv := NewServer(Config{})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	defer srv.Close()

	paths := []string{"/", "/static/style.css", "/static/app.js", "/static/overrides.js", "/static/processes.js"}
	for _, p := range paths {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatalf("GET %s failed: %v", p, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read %s body: %v", p, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", p, resp.StatusCode)
		}
		if strings.HasSuffix(p, ".js") {
			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "javascript") {
				t.Fatalf("JS asset %s Content-Type = %q, want javascript MIME type", p, ct)
			}
		}
		content := string(body)
		if strings.Contains(content, "http://") || strings.Contains(content, "https://") {
			t.Fatalf("asset %s contains external URL reference, violating offline constraint", p)
		}
	}

	for _, iconPath := range []string{"/favicon.ico", "/static/logo.svg"} {
		resp, err := http.Get(ts.URL + iconPath)
		if err != nil {
			t.Fatalf("GET %s failed: %v", iconPath, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read %s body: %v", iconPath, err)
		}
		if resp.StatusCode != http.StatusOK || len(body) == 0 {
			t.Fatalf("GET %s status=%d len=%d, want 200 and non-empty", iconPath, resp.StatusCode, len(body))
		}
	}
}

func TestConnectionsListClearAndSSEStream(t *testing.T) {
	tr := tracker.New(200)
	srv := NewServer(Config{Tracker: tr})
	baseURL := startDashboard(t, srv)
	client := dashboardClient(t, srv, baseURL)

	// 1. 初始为空数组而非 null
	resp, err := client.Get(baseURL + "/api/connections")
	if err != nil {
		t.Fatalf("GET /api/connections: %v", err)
	}
	var initData ConnectionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&initData); err != nil {
		t.Fatalf("decode initial connections: %v", err)
	}
	_ = resp.Body.Close()
	if initData.Total != 0 || initData.Connections == nil || len(initData.Connections) != 0 {
		t.Fatalf("expected empty non-nil slice, got %+v", initData)
	}

	// 2. 测试 SSE 实时流推送
	sseCtx, sseCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer sseCancel()
	sseReq, _ := http.NewRequestWithContext(sseCtx, http.MethodGet, baseURL+"/api/connections/stream", nil)
	sseResp, err := client.Do(sseReq)
	if err != nil {
		t.Fatalf("open SSE stream: %v", err)
	}
	defer sseResp.Body.Close()

	reader := bufio.NewReader(sseResp.Body)
	readSSEDataLine := func() ConnectionsResponse {
		t.Helper()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read SSE line: %v", err)
			}
			if strings.HasPrefix(line, "data: ") {
				raw := strings.TrimSpace(strings.TrimPrefix(line, "data: "))
				var snap ConnectionsResponse
				if err := json.Unmarshal([]byte(raw), &snap); err != nil {
					t.Fatalf("unmarshal SSE json: %v", err)
				}
				return snap
			}
		}
	}

	// 首次快照为空
	firstSnap := readSSEDataLine()
	if firstSnap.Total != 0 {
		t.Fatalf("expected initial SSE total 0, got %d", firstSnap.Total)
	}

	// 写入连接并更新错误状态
	id1 := tr.Start(tracker.StartEntry{
		Target:   "db.internal:3306",
		Protocol: tracker.ProtoFastPath,
		Action:   tracker.ActionDirect,
	})
	_ = readSSEDataLine() // 消费 Start 推送

	tr.Finish(id1, errors.New("connection reset"))
	errSnap := readSSEDataLine()
	if errSnap.Total != 1 || errSnap.Connections[0].Status != tracker.StatusError || errSnap.Connections[0].Error != "connection reset" {
		t.Fatalf("unexpected SSE error snapshot: %+v", errSnap)
	}

	// 3. 调用 POST /api/connections/clear 清空记录
	clearResp, err := client.Post(baseURL+"/api/connections/clear", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/connections/clear: %v", err)
	}
	_ = clearResp.Body.Close()
	if clearResp.StatusCode != http.StatusOK {
		t.Fatalf("clear status = %d, want 200", clearResp.StatusCode)
	}

	clearedSnap := readSSEDataLine()
	if clearedSnap.Total != 0 {
		t.Fatalf("expected total 0 after clear, got %d", clearedSnap.Total)
	}
}

func TestConfigValidationAndEndToEndHotReload(t *testing.T) {
	// 启动两个模拟 Burp 服务端 (burpA, burpB) 以及一个真实直连后端服务端 (directTarget)
	startMockProxy := func(tag string, counter *atomic.Int32) net.Listener {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen %s: %v", tag, err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				counter.Add(1)
				go func(conn net.Conn) {
					defer conn.Close()
					br := bufio.NewReader(conn)
					req, err := http.ReadRequest(br)
					if err != nil || req.Method != http.MethodConnect {
						return
					}
					_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
					_, _ = http.ReadRequest(br)
					body := "via-" + tag
					_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
				}(c)
			}
		}()
		return ln
	}

	var burpAHits, burpBHits, directHits atomic.Int32
	burpALn := startMockProxy("burpA", &burpAHits)
	burpBLn := startMockProxy("burpB", &burpBHits)

	directLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen direct target: %v", err)
	}
	defer directLn.Close()
	go func() {
		for {
			c, err := directLn.Accept()
			if err != nil {
				return
			}
			directHits.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				_, _ = http.ReadRequest(br)
				const body = "via-direct-target"
				_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(c)
		}
	}()

	_, directPortStr, _ := net.SplitHostPort(directLn.Addr().String())
	var directPort int
	_, _ = fmt.Sscanf(directPortStr, "%d", &directPort)

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks: %v", err)
	}
	webLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen web: %v", err)
	}

	tr := tracker.New(200)
	det := detector.NewDefault()
	fwd := forwarder.New(forwarder.Config{BurpAddr: burpALn.Addr().String()})

	socksSrv := socks5.NewServer(socks5.Config{
		ListenAddr:  socksLn.Addr().String(),
		Detector:    det,
		Forwarder:   fwd,
		BypassAddrs: []string{webLn.Addr().String()},
		Hooks: socks5.LifecycleHooks{
			OnConnStart: func(ev socks5.ConnStartEvent) uint64 {
				return tr.Start(tracker.StartEntry{
					Timestamp:  ev.Time,
					ClientAddr: ev.ClientAddr,
					Target:     ev.TargetAddr,
					Protocol:   ev.Protocol,
					Action:     string(ev.Action),
				})
			},
			OnConnEnd: func(id uint64, err error) {
				tr.Finish(id, err)
			},
		},
	})
	go func() { _ = socksSrv.Serve(socksLn) }()
	defer socksSrv.Close()

	webSrv := NewServer(Config{
		ListenAddr:  webLn.Addr().String(),
		Tracker:     tr,
		Detector:    det,
		Forwarder:   fwd,
		SocksServer: socksSrv,
	})
	go func() { _ = webSrv.Serve(webLn) }()
	defer webSrv.Close()

	webBase := "http://" + webLn.Addr().String()
	client := dashboardClient(t, webSrv, webBase)

	// 辅助函数：通过 SOCKS5 发起 HTTP GET 请求并返回响应体
	sendHTTPViaSocks := func(targetHost string, targetPort uint16) string {
		t.Helper()
		conn, err := net.DialTimeout("tcp", socksSrv.Addr(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial socks: %v", err)
		}
		defer conn.Close()
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
		var g [2]byte
		_, _ = io.ReadFull(conn, g[:])

		ip4 := net.ParseIP(targetHost).To4()
		req := []byte{0x05, 0x01, 0x00, 0x01}
		req = append(req, ip4...)
		var pb [2]byte
		binary.BigEndian.PutUint16(pb[:], targetPort)
		req = append(req, pb[:]...)
		_, _ = conn.Write(req)

		var rep [10]byte
		if _, err := io.ReadFull(conn, rep[:]); err != nil || rep[1] != 0x00 {
			t.Fatalf("socks connect failed: err=%v rep=%x", err, rep)
		}

		_, _ = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n", targetHost, targetPort)
		httpResp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read http response: %v", err)
		}
		defer httpResp.Body.Close()
		body, _ := io.ReadAll(httpResp.Body)
		return string(body)
	}

	postConfig := func(payload string) (*http.Response, ConfigResponse) {
		t.Helper()
		resp, err := client.Post(webBase+"/api/config", "application/json", bytes.NewBufferString(payload))
		if err != nil {
			t.Fatalf("POST /api/config: %v", err)
		}
		defer resp.Body.Close()
		var cfg ConfigResponse
		if resp.StatusCode == http.StatusOK {
			_ = json.NewDecoder(resp.Body).Decode(&cfg)
		}
		return resp, cfg
	}

	// 阶段 1：默认路由到 burpA
	if got := sendHTTPViaSocks("127.0.0.1", uint16(directPort)); got != "via-burpA" {
		t.Fatalf("stage 1 got %q, want via-burpA", got)
	}

	// 阶段 2：校验非法参数应返回 400 且不破坏已有配置
	badCases := []string{
		`{"burpAddr": "invalid-addr"}`,
		fmt.Sprintf(`{"burpAddr": %q}`, socksSrv.Addr()),
		`{"directPorts": [0, 3306]}`,
		`{"directPorts": [70000]}`,
	}
	for _, bad := range badCases {
		r, _ := postConfig(bad)
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("payload %s status = %d, want 400", bad, r.StatusCode)
		}
	}

	// 阶段 3：热更新 BurpAddr 为 burpB（无需重启 SOCKS5）
	r, cfg := postConfig(fmt.Sprintf(`{"burpAddr": %q}`, burpBLn.Addr().String()))
	if r.StatusCode != http.StatusOK || cfg.BurpAddr != burpBLn.Addr().String() {
		t.Fatalf("hot update burpB failed: status=%d cfg=%+v", r.StatusCode, cfg)
	}
	if got := sendHTTPViaSocks("127.0.0.1", uint16(directPort)); got != "via-burpB" {
		t.Fatalf("stage 3 got %q, want via-burpB", got)
	}

	// 阶段 4：热更新 DirectPorts 加入 directPort → 立即跳过 Peek 直连目标服务
	r, cfg = postConfig(fmt.Sprintf(`{"directPorts": [3306, %d]}`, directPort))
	if r.StatusCode != http.StatusOK {
		t.Fatalf("hot update directPorts status = %d", r.StatusCode)
	}
	if got := sendHTTPViaSocks("127.0.0.1", uint16(directPort)); got != "via-direct-target" {
		t.Fatalf("stage 4 whitelist hot-reload got %q, want via-direct-target", got)
	}

	// 阶段 5：清空 DirectPorts 但开启 BypassAll=true → 即使 HTTP 流量也立即走 Direct
	r, cfg = postConfig(`{"directPorts": [], "bypassAll": true}`)
	if r.StatusCode != http.StatusOK || !cfg.BypassAll || len(cfg.DirectPorts) != 0 {
		t.Fatalf("hot update bypassAll failed: status=%d cfg=%+v", r.StatusCode, cfg)
	}
	if got := sendHTTPViaSocks("127.0.0.1", uint16(directPort)); got != "via-direct-target" {
		t.Fatalf("stage 5 bypassAll got %q, want via-direct-target", got)
	}

	// 阶段 6：关闭 BypassAll，测试经由 SOCKS5 访问 Web 看板自身地址自动回环直连排除，不进 Burp
	_, _ = postConfig(`{"bypassAll": false}`)
	_, webPortStr, _ := net.SplitHostPort(webLn.Addr().String())
	var webPort uint16
	_, _ = fmt.Sscanf(webPortStr, "%d", &webPort)
	burpBCountBefore := burpBHits.Load()
	dashboardHTML := sendHTTPViaSocks("127.0.0.1", webPort)
	if !strings.Contains(dashboardHTML, "CS-Burp-Router") {
		t.Fatalf("expected Web UI HTML via loopback bypass")
	}
	if burpBHits.Load() != burpBCountBefore {
		t.Fatalf("accessing Web UI via SOCKS5 leaked into Burp!")
	}

	// 等待异步 OnConnEnd 完成状态更新并验证 Tracker 记录均已归档为 Closed
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		recs := tr.List()
		allDone := len(recs) == 5
		for _, rec := range recs {
			if rec.Status != tracker.StatusClosed {
				allDone = false
				break
			}
		}
		if allDone {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	recs := tr.List()
	if len(recs) != 5 {
		t.Fatalf("expected 5 tracked connections, got %d", len(recs))
	}
	if recs[0].Protocol != tracker.ProtoLoopback || recs[0].Action != tracker.ActionDirect {
		t.Fatalf("latest record should be Web UI Loopback/Direct, got %+v", recs[0])
	}
}

type webMockBridgeProc struct {
	pid     int
	stdoutR *io.PipeReader
	stdoutW *io.PipeWriter
	exitCh  chan error
}

func (p *webMockBridgeProc) PID() int          { return p.pid }
func (p *webMockBridgeProc) Stdout() io.Reader { return p.stdoutR }
func (p *webMockBridgeProc) Stderr() io.Reader { return nil }
func (p *webMockBridgeProc) Terminate() error {
	_ = p.stdoutW.Close()
	select {
	case p.exitCh <- nil:
	default:
	}
	return nil
}
func (p *webMockBridgeProc) Kill() error { return p.Terminate() }
func (p *webMockBridgeProc) Wait() error { return <-p.exitCh }

func TestBridgeAPIEndpoints(t *testing.T) {
	var pidSeq atomic.Int32
	pidSeq.Store(4000)
	var mockIsAdmin atomic.Bool // 初始为 false（非管理员），随后切换为 true 验证动态响应

	mgr := bridge.NewManager(bridge.ManagerConfig{
		SocksAddr:        "127.0.0.1:10808",
		TempDir:          t.TempDir(),
		SkipBinaryLookup: true,
		AdminChecker:     func() bool { return mockIsAdmin.Load() },
		Runner: func(binaryPath string, args []string) (bridge.ManagedProcess, error) {
			r, w := io.Pipe()
			mp := &webMockBridgeProc{
				pid:     int(pidSeq.Add(1)),
				stdoutR: r,
				stdoutW: w,
				exitCh:  make(chan error, 1),
			}
			go func() {
				_, _ = fmt.Fprintln(w, "ProxyBridge WinDivert filter active")
			}()
			return mp, nil
		},
	})
	defer mgr.Stop()

	srv := NewServer(Config{
		Bridge: mgr,
		ProcessDetailLister: func(ctx context.Context) ([]bridge.ProcessInfo, error) {
			return []bridge.ProcessInfo{
				{Name: "apifox.exe", Description: "Apifox", HasWindow: true, WindowTitle: "Apifox"},
				{Name: "client.exe", Description: "NetEase Cloud Music"},
				{Name: "java.exe", Description: "Java(TM) Platform SE binary"},
			}, nil
		},
	})
	baseURL := startDashboard(t, srv)
	client := dashboardClient(t, srv, baseURL)

	// 1. GET /api/bridge/status 初始为 Stopped 且 is_admin=false
	stResp, err := client.Get(baseURL + "/api/bridge/status")
	if err != nil {
		t.Fatalf("GET /api/bridge/status: %v", err)
	}
	rawStatusBytes, _ := io.ReadAll(stResp.Body)
	_ = stResp.Body.Close()

	var rawMap map[string]any
	if err := json.Unmarshal(rawStatusBytes, &rawMap); err != nil {
		t.Fatalf("unmarshal raw status map: %v", err)
	}
	if isAdminVal, ok := rawMap["is_admin"].(bool); !ok || isAdminVal != false {
		t.Fatalf("expected raw JSON is_admin=false, got (%T)%v", rawMap["is_admin"], rawMap["is_admin"])
	}

	var st bridge.StatusSnapshot
	_ = json.Unmarshal(rawStatusBytes, &st)
	if st.State != bridge.StateStopped || st.PID != 0 || st.IsAdmin {
		t.Fatalf("expected initial Stopped state with IsAdmin=false, got %+v", st)
	}

	// 切换 mockIsAdmin 为 true，再次请求验证 GET /api/bridge/status 返回 is_admin=true
	mockIsAdmin.Store(true)
	stAdminResp, err := client.Get(baseURL + "/api/bridge/status")
	if err != nil {
		t.Fatalf("GET /api/bridge/status (admin): %v", err)
	}
	var stAdmin bridge.StatusSnapshot
	_ = json.NewDecoder(stAdminResp.Body).Decode(&stAdmin)
	_ = stAdminResp.Body.Close()
	if !stAdmin.IsAdmin {
		t.Fatalf("expected IsAdmin=true after switching mockIsAdmin, got %+v", stAdmin)
	}

	// 2. GET /api/bridge/processes 返回进程列表
	pResp, err := client.Get(baseURL + "/api/bridge/processes")
	if err != nil {
		t.Fatalf("GET /api/bridge/processes: %v", err)
	}
	var pData BridgeProcessesResponse
	_ = json.NewDecoder(pResp.Body).Decode(&pData)
	_ = pResp.Body.Close()
	if len(pData.Processes) != 3 || pData.Processes[1] != "client.exe" {
		t.Fatalf("unexpected processes response: %+v", pData)
	}
	if len(pData.Items) != 3 || pData.Items[1].Description != "NetEase Cloud Music" || !pData.Items[0].HasWindow {
		t.Fatalf("unexpected process detail items: %+v", pData.Items)
	}

	// 3. POST /api/bridge/start 空进程列表应返回 400
	badStart, err := client.Post(baseURL+"/api/bridge/start", "application/json", bytes.NewBufferString(`{"processes": []}`))
	if err != nil {
		t.Fatalf("POST empty start: %v", err)
	}
	_ = badStart.Body.Close()
	if badStart.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty start status = %d, want 400", badStart.StatusCode)
	}

	// 4. POST /api/bridge/start 正常启动（并测试显式传 target_domains: ""）
	startResp, err := client.Post(
		baseURL+"/api/bridge/start",
		"application/json",
		bytes.NewBufferString(`{"processes": ["client.exe", "java.exe"], "target_domains": ""}`),
	)
	if err != nil {
		t.Fatalf("POST /api/bridge/start: %v", err)
	}
	var runningSt bridge.StatusSnapshot
	_ = json.NewDecoder(startResp.Body).Decode(&runningSt)
	_ = startResp.Body.Close()
	if startResp.StatusCode != http.StatusOK {
		t.Fatalf("start status = %d, want 200", startResp.StatusCode)
	}
	if runningSt.State != bridge.StateRunning || runningSt.PID != 4001 || runningSt.TargetDomains != "" {
		t.Fatalf("unexpected running snapshot: %+v", runningSt)
	}

	// 5. 运行中再次调用 POST /api/bridge/start 热重启并更新进程列表
	restartResp, err := client.Post(
		baseURL+"/api/bridge/start",
		"application/json",
		bytes.NewBufferString(`{"processes": ["navicat.exe"]}`),
	)
	if err != nil {
		t.Fatalf("POST restart: %v", err)
	}
	var restartedSt bridge.StatusSnapshot
	_ = json.NewDecoder(restartResp.Body).Decode(&restartedSt)
	_ = restartResp.Body.Close()
	if restartedSt.State != bridge.StateRunning || restartedSt.PID != 4002 || restartedSt.TargetDomains != "*" {
		t.Fatalf("unexpected restarted snapshot: %+v", restartedSt)
	}

	// 6. POST /api/bridge/stop 停止接管
	stopResp, err := client.Post(baseURL+"/api/bridge/stop", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/bridge/stop: %v", err)
	}
	var stoppedSt bridge.StatusSnapshot
	_ = json.NewDecoder(stopResp.Body).Decode(&stoppedSt)
	_ = stopResp.Body.Close()
	if stopResp.StatusCode != http.StatusOK || stoppedSt.State != bridge.StateStopped || stoppedSt.PID != 0 {
		t.Fatalf("unexpected stopped snapshot: status=%d snap=%+v", stopResp.StatusCode, stoppedSt)
	}
}

type webMemCertStore struct {
	installedDER []byte
}

func (s *webMemCertStore) Inspect(fp string) (bool, []string, int, error) {
	if len(s.installedDER) == 0 {
		return false, nil, 0, nil
	}
	parsed, err := cert.ParseAndValidateCA(s.installedDER)
	if err != nil {
		return false, nil, 0, nil
	}
	if fp != "" && strings.EqualFold(parsed.FingerprintSHA1, fp) {
		return true, []string{"LocalMachine"}, 1, nil
	}
	return false, nil, 1, nil
}

func (s *webMemCertStore) InstallRootCA(rawDER []byte, preferMachine bool) (string, error) {
	s.installedDER = append([]byte(nil), rawDER...)
	if preferMachine {
		return "LocalMachine", nil
	}
	return "CurrentUser", nil
}

func (s *webMemCertStore) RemoveBurpCAs(fp string, isAdmin bool) (int, string, error) {
	if len(s.installedDER) == 0 {
		return 0, "", nil
	}
	s.installedDER = nil
	return 1, "", nil
}

type webCleanupCertStore struct {
	webMemCertStore
	removeErr error
}

func (s *webCleanupCertStore) RemoveBurpCAs(string, bool) (int, string, error) {
	return 1, "系统信任库中仍有匹配的证书", s.removeErr
}

func TestCertCleanupPartialResponse(t *testing.T) {
	for _, tc := range []struct {
		name       string
		removeErr  error
		wantStatus int
	}{
		{name: "remaining trust", removeErr: cert.ErrCleanupIncomplete, wantStatus: http.StatusConflict},
		{name: "store error", removeErr: errors.New("fake certificate-store failure"), wantStatus: http.StatusInternalServerError},
		{name: "best-effort warning", wantStatus: http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			certMgr := cert.NewManager(cert.ManagerConfig{
				Store: &webCleanupCertStore{removeErr: tc.removeErr},
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					return nil, errors.New("mock Burp is offline")
				},
			})
			srv := NewServer(Config{Cert: certMgr})
			baseURL := startDashboard(t, srv)
			client := dashboardClient(t, srv, baseURL)
			resp, err := client.Post(baseURL+"/api/cert/uninstall", "application/json", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var result certActionErrorResponse
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.wantStatus || result.RemovedCount != 1 || result.Warning == "" ||
				(result.Error == "") != (tc.removeErr == nil) {
				t.Fatalf("unexpected cleanup outcome: HTTP %d, %+v", resp.StatusCode, result)
			}
		})
	}
}

func TestStalledCertInstallDoesNotBlockConfig(t *testing.T) {
	fetchStarted := make(chan struct{}, 1)
	release := make(chan struct{})
	burp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case fetchStarted <- struct{}{}:
		default:
		}
		select {
		case <-release:
			_, _ = io.WriteString(w, "this response is deliberately not a certificate")
		case <-r.Context().Done():
		}
	}))
	defer burp.Close()
	defer close(release)

	burpAddr := strings.TrimPrefix(burp.URL, "http://")
	srv := NewServer(Config{
		Forwarder: forwarder.New(forwarder.Config{BurpAddr: burpAddr}),
		Cert: cert.NewManager(cert.ManagerConfig{
			Store:        &webMemCertStore{},
			FetchTimeout: 10 * time.Second,
		}),
	})
	baseURL := startDashboard(t, srv)
	client := dashboardClient(t, srv, baseURL)
	installCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body := fmt.Sprintf(`{"burpAddr":%q,"fingerprintSHA256":%q}`, burpAddr, strings.Repeat("0", 64))
	installReq, err := http.NewRequestWithContext(installCtx, http.MethodPost, baseURL+"/api/cert/install", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	installReq.Header.Set("Content-Type", "application/json")
	installDone := make(chan struct{})
	go func() {
		defer close(installDone)
		if resp, err := client.Do(installReq); err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-fetchStarted:
	case <-installCtx.Done():
		t.Fatal("certificate fetch did not start")
	}

	configClient := &http.Client{Transport: client.Transport, Timeout: time.Second}
	const updatedAddr = "127.0.0.1:2"
	resp, err := configClient.Post(baseURL+"/api/config", "application/json", strings.NewReader(`{"burpAddr":"`+updatedAddr+`"}`))
	if err != nil {
		t.Fatalf("config POST was blocked by the certificate fetch: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("config POST status = %d, want 200", resp.StatusCode)
	}

	resp, err = configClient.Get(baseURL + "/api/config")
	if err != nil {
		t.Fatalf("config GET was blocked by the certificate fetch: %v", err)
	}
	defer resp.Body.Close()
	var cfg ConfigResponse
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || cfg.BurpAddr != updatedAddr {
		t.Fatalf("unexpected config result: HTTP %d, %+v", resp.StatusCode, cfg)
	}
	select {
	case <-installDone:
		t.Fatal("certificate fetch unexpectedly completed before the config update")
	default:
	}
}

func TestCertAPIEndpoints(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "PortSwigger CA", Organization: []string{"PortSwigger"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	burpCertLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock burp cert: %v", err)
	}
	defer burpCertLn.Close()
	go func() {
		for {
			c, err := burpCertLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = http.ReadRequest(bufio.NewReader(conn))
				_, _ = fmt.Fprintf(conn, "HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n", len(caDER))
				_, _ = conn.Write(caDER)
			}(c)
		}
	}()

	memStore := &webMemCertStore{}
	certMgr := cert.NewManager(cert.ManagerConfig{
		Store:        memStore,
		AdminChecker: func() bool { return true },
	})
	fwd := forwarder.New(forwarder.Config{BurpAddr: burpCertLn.Addr().String()})
	srv := NewServer(Config{
		Forwarder: fwd,
		Cert:      certMgr,
	})
	baseURL := startDashboard(t, srv)
	client := dashboardClient(t, srv, baseURL)

	// 1. GET /api/cert/status 初始未安装但 Burp 可达
	stResp, err := client.Get(baseURL + "/api/cert/status")
	if err != nil {
		t.Fatalf("GET /api/cert/status: %v", err)
	}
	var st cert.Status
	_ = json.NewDecoder(stResp.Body).Decode(&st)
	_ = stResp.Body.Close()
	if !st.BurpReachable || st.Installed || st.CommonName != "PortSwigger CA" || st.FingerprintSHA256 == "" {
		t.Fatalf("unexpected initial cert status: %+v", st)
	}

	// 2. GET /api/cert/download 可直接下载原始 DER 证书文件
	dlResp, err := client.Get(baseURL + "/api/cert/download")
	if err != nil {
		t.Fatalf("GET /api/cert/download: %v", err)
	}
	dlBytes, _ := io.ReadAll(dlResp.Body)
	_ = dlResp.Body.Close()
	if dlResp.StatusCode != http.StatusOK || !bytes.Equal(dlBytes, caDER) {
		t.Fatalf("unexpected cert download response: status=%d len=%d", dlResp.StatusCode, len(dlBytes))
	}

	postInstall := func(addr, fingerprint string, want int) cert.ActionResponse {
		t.Helper()
		body, err := json.Marshal(CertInstallRequest{BurpAddr: addr, FingerprintSHA256: fingerprint})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Post(baseURL+"/api/cert/install", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("certificate install HTTP status = %d, want %d", resp.StatusCode, want)
		}
		var data cert.ActionResponse
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			t.Fatal(err)
		}
		return data
	}

	postInstall(st.BurpAddr, "", http.StatusBadRequest)
	postInstall(st.BurpAddr, strings.Repeat("0", 64), http.StatusConflict)
	postInstall("localhost:8080", st.FingerprintSHA256, http.StatusConflict)
	// 3. POST /api/cert/install 确认指纹后安装
	instData := postInstall(st.BurpAddr, st.FingerprintSHA256, http.StatusOK)
	if !instData.Installed || instData.ActionScope != "LocalMachine" {
		t.Fatalf("unexpected cert install response: %+v", instData)
	}

	// 4. POST /api/cert/uninstall 一键撤场卸载
	uninstResp, err := client.Post(baseURL+"/api/cert/uninstall", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/cert/uninstall: %v", err)
	}
	var uninstData cert.ActionResponse
	_ = json.NewDecoder(uninstResp.Body).Decode(&uninstData)
	_ = uninstResp.Body.Close()
	if uninstResp.StatusCode != http.StatusOK || uninstData.RemovedCount != 1 || uninstData.Installed {
		t.Fatalf("unexpected cert uninstall response: status=%d data=%+v", uninstResp.StatusCode, uninstData)
	}
}

func TestOverridesAPIEndpointsAndValidation(t *testing.T) {
	socksSrv := socks5.NewServer(socks5.Config{})
	defer socksSrv.Close()

	srv := NewServer(Config{
		SocksServer: socksSrv,
	})
	baseURL := startDashboard(t, srv)
	client := dashboardClient(t, srv, baseURL)

	// 1. 初始 GET /api/overrides 应返回空数组（非 null）
	resp, err := client.Get(baseURL + "/api/overrides")
	if err != nil {
		t.Fatalf("GET /api/overrides: %v", err)
	}
	var initData OverridesResponse
	if err := json.NewDecoder(resp.Body).Decode(&initData); err != nil {
		t.Fatalf("decode GET /api/overrides: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || initData.Overrides == nil || len(initData.Overrides) != 0 {
		t.Fatalf("unexpected initial overrides: status=%d data=%+v", resp.StatusCode, initData)
	}

	// 2. POST 非法参数应返回 400
	for _, bad := range []string{
		`{"target": "", "action": "Direct"}`,
		`{"target": "10.0.0.1:99999", "action": "Direct"}`,
		`{"target": "10.0.0.1:443", "action": "Reject"}`,
		`not-json`,
	} {
		r, err := client.Post(baseURL+"/api/overrides", "application/json", strings.NewReader(bad))
		if err != nil {
			t.Fatalf("POST bad override %s: %v", bad, err)
		}
		_ = r.Body.Close()
		if r.StatusCode != http.StatusBadRequest {
			t.Fatalf("bad override %s status = %d, want 400", bad, r.StatusCode)
		}
	}

	// 3. POST 添加按 host:port 与按 host 的规则，并支持更新已有规则
	postOverride := func(payload string) OverridesResponse {
		t.Helper()
		r, err := client.Post(baseURL+"/api/overrides", "application/json", strings.NewReader(payload))
		if err != nil {
			t.Fatalf("POST /api/overrides: %v", err)
		}
		defer r.Body.Close()
		if r.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(r.Body)
			t.Fatalf("POST /api/overrides status=%d body=%s", r.StatusCode, body)
		}
		var out OverridesResponse
		if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
			t.Fatalf("decode POST /api/overrides: %v", err)
		}
		return out
	}

	res1 := postOverride(`{"target": "API.Example.COM:443", "action": "Direct"}`)
	if res1.Rule == nil || res1.Rule.Target != "api.example.com:443" || res1.Rule.Action != socks5.ActionDirect {
		t.Fatalf("unexpected rule1: %+v", res1)
	}

	res2 := postOverride(`{"target": "192.168.1.245", "action": "Burp"}`)
	if len(res2.Overrides) != 2 {
		t.Fatalf("expected 2 overrides, got %+v", res2.Overrides)
	}

	// 更新同一目标动作：Direct -> Burp
	res3 := postOverride(`{"target": "api.example.com:443", "action": "Burp"}`)
	if len(res3.Overrides) != 2 {
		t.Fatalf("updating existing target should not duplicate rule: %+v", res3.Overrides)
	}
	if act, ok := socksSrv.MatchOverride("api.example.com", 443); !ok || act != socks5.ActionBurp {
		t.Fatalf("socks5 server did not reflect updated override: act=%q ok=%v", act, ok)
	}

	// 4. DELETE ?target=... 删除指定规则
	delReq, _ := http.NewRequest(http.MethodDelete, baseURL+"/api/overrides?target="+url.QueryEscape("api.example.com:443"), nil)
	delResp, err := client.Do(delReq)
	if err != nil {
		t.Fatalf("DELETE single override: %v", err)
	}
	var delData OverridesResponse
	_ = json.NewDecoder(delResp.Body).Decode(&delData)
	_ = delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK || delData.Deleted == nil || !*delData.Deleted || len(delData.Overrides) != 1 {
		t.Fatalf("unexpected delete single response: status=%d data=%+v", delResp.StatusCode, delData)
	}

	// 5. DELETE 不传 target 一键清空全部规则
	clearReq, _ := http.NewRequest(http.MethodDelete, baseURL+"/api/overrides", nil)
	clearResp, err := client.Do(clearReq)
	if err != nil {
		t.Fatalf("DELETE clear overrides: %v", err)
	}
	var clearData OverridesResponse
	_ = json.NewDecoder(clearResp.Body).Decode(&clearData)
	_ = clearResp.Body.Close()
	if clearResp.StatusCode != http.StatusOK || !clearData.Cleared || len(clearData.Overrides) != 0 {
		t.Fatalf("unexpected clear overrides response: status=%d data=%+v", clearResp.StatusCode, clearData)
	}
	if len(socksSrv.Overrides()) != 0 {
		t.Fatalf("socks5 server overrides not cleared: %+v", socksSrv.Overrides())
	}
}

func TestDeleteOverridesQuery(t *testing.T) {
	for _, tt := range []struct {
		name      string
		query     string
		wantCode  int
		wantCount int
	}{
		{"empty target", "?target=", http.StatusBadRequest, 2},
		{"blank target", "?target=%20%20", http.StatusBadRequest, 2},
		{"clear false", "?clear=false", http.StatusBadRequest, 2},
		{"all false", "?all=false", http.StatusBadRequest, 2},
		{"unknown parameter", "?other=1", http.StatusBadRequest, 2},
		{"malformed query", "?target=%zz", http.StatusBadRequest, 2},
		{"false with target", "?clear=false&target=first.example:443", http.StatusOK, 1},
		{"implicit clear", "", http.StatusOK, 0},
		{"clear true with target", "?clear=%20TrUe%20&target=first.example:443", http.StatusOK, 0},
		{"all one", "?all=1", http.StatusOK, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := NewServer(Config{})
			t.Cleanup(func() { _ = srv.Close() })
			for _, target := range []string{"first.example:443", "second.example:443"} {
				if _, err := srv.standaloneOverrides.Set(target, socks5.ActionDirect); err != nil {
					t.Fatalf("set override for %s: %v", target, err)
				}
			}

			resp := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodDelete, "/api/overrides"+tt.query, nil)
			srv.handleOverrides(resp, req)
			if resp.Code != tt.wantCode {
				t.Errorf("status = %d, want %d (body %s)", resp.Code, tt.wantCode, resp.Body)
			}
			if rules := srv.listOverrides(); len(rules) != tt.wantCount {
				t.Errorf("remaining rules = %+v, want %d rules", rules, tt.wantCount)
			}
		})
	}
}

func TestBridgeProcessesActiveOutboundResponseSchemaAndSorting(t *testing.T) {
	srv := NewServer(Config{
		ProcessDetailLister: func(ctx context.Context) ([]bridge.ProcessInfo, error) {
			return []bridge.ProcessInfo{
				{Name: "idle.exe"},
				{Name: "client.exe", ActiveConnections: 2, SampleTargets: []string{"10.0.0.1:443"}},
				{Name: "java.exe", ActiveConnections: 5, SampleTargets: []string{"192.168.1.245:1433", "10.0.0.2:8080"}},
				{Name: "alpha.exe", ActiveConnections: 2, SampleTargets: []string{"10.0.0.9:80"}},
			}, nil
		},
	})
	baseURL := startDashboard(t, srv)
	client := dashboardClient(t, srv, baseURL)

	resp, err := client.Get(baseURL + "/api/bridge/processes")
	if err != nil {
		t.Fatalf("GET /api/bridge/processes: %v", err)
	}
	rawBody, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// 验证保留旧字段 processes 且新增结构化 items 按 active_connections 降序、name 升序排列
	var parsed BridgeProcessesResponse
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		t.Fatalf("unmarshal processes response: %v", err)
	}
	wantNames := []string{"java.exe", "alpha.exe", "client.exe", "idle.exe"}
	if len(parsed.Processes) != len(wantNames) || len(parsed.Items) != len(wantNames) {
		t.Fatalf("unexpected lengths: processes=%v items=%+v", parsed.Processes, parsed.Items)
	}
	for i, w := range wantNames {
		if parsed.Processes[i] != w || parsed.Items[i].Name != w {
			t.Fatalf("order[%d] got proc=%q item=%q, want %q", i, parsed.Processes[i], parsed.Items[i].Name, w)
		}
	}
	if parsed.Items[0].ActiveConnections != 5 || len(parsed.Items[0].SampleTargets) != 2 {
		t.Fatalf("unexpected top active process item: %+v", parsed.Items[0])
	}
	if parsed.Items[3].SampleTargets == nil {
		t.Fatalf("expected non-nil empty sample_targets slice for idle process")
	}

	// 验证 JSON 原始字段名包含 active_connections 与 sample_targets
	var rawDoc map[string]any
	if err := json.Unmarshal(rawBody, &rawDoc); err != nil {
		t.Fatalf("unmarshal raw map: %v", err)
	}
	rawItems := rawDoc["items"].([]any)
	first := rawItems[0].(map[string]any)
	if first["active_connections"] != float64(5) {
		t.Fatalf("raw JSON active_connections = %v, want 5", first["active_connections"])
	}
	if _, ok := first["sample_targets"].([]any); !ok {
		t.Fatalf("raw JSON sample_targets missing or wrong type: %v", first["sample_targets"])
	}
}

func TestBridgeProcessesNameListerOrdering(t *testing.T) {
	srv := NewServer(Config{
		ProcessLister: func(context.Context) ([]string, error) {
			return []string{"zeta.exe", "Alpha.exe"}, nil
		},
	})
	t.Cleanup(func() { _ = srv.Close() })

	resp := httptest.NewRecorder()
	srv.handleBridgeProcesses(resp, httptest.NewRequest(http.MethodGet, "/api/bridge/processes", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", resp.Code, resp.Body)
	}
	var parsed BridgeProcessesResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		t.Fatalf("decode process response: %v", err)
	}
	wantNames := []string{"Alpha.exe", "zeta.exe"}
	if len(parsed.Processes) != len(wantNames) || len(parsed.Items) != len(wantNames) {
		t.Fatalf("unexpected lengths: processes=%v items=%+v", parsed.Processes, parsed.Items)
	}
	for i, name := range wantNames {
		if parsed.Processes[i] != name || parsed.Items[i].Name != name {
			t.Errorf("order[%d]: process=%q item=%q, want %q", i, parsed.Processes[i], parsed.Items[i].Name, name)
		}
	}
}

// 端到端验证边界 1：带 SNI 的纯 IP TLS 连接命中 /api/connections 后，按 Target (IP:Port) 下发 Direct 覆盖规则立即生效且跳过 Peek。
func TestSNIBareIPOverrideEndToEnd(t *testing.T) {
	// 1. Mock Burp CONNECT 代理（读取首包并回复标记）
	burpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen burp: %v", err)
	}
	defer burpLn.Close()
	var burpHits atomic.Int32
	go func() {
		for {
			c, err := burpLn.Accept()
			if err != nil {
				return
			}
			burpHits.Add(1)
			go func(conn net.Conn) {
				defer conn.Close()
				br := bufio.NewReader(conn)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				_, _ = conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				buf := make([]byte, 1024)
				_, _ = br.Read(buf)
				_, _ = conn.Write([]byte("BURP-OK"))
			}(c)
		}
	}()

	// 2. Mock 直连目标服务（直接回写 Banner，验证 Direct 覆盖跳过 200ms Peek）
	directLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen direct: %v", err)
	}
	defer directLn.Close()
	go func() {
		for {
			c, err := directLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte("DIRECT-OK"))
			}(c)
		}
	}()

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks: %v", err)
	}
	webLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen web: %v", err)
	}

	baseDialer := &net.Dialer{Timeout: 2 * time.Second}
	tr := tracker.New(50)
	det := detector.NewDefault()
	fwd := forwarder.New(forwarder.Config{
		BurpAddr: burpLn.Addr().String(),
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == "10.88.0.245:443" {
				return baseDialer.DialContext(ctx, network, directLn.Addr().String())
			}
			return baseDialer.DialContext(ctx, network, address)
		},
	})

	socksSrv := socks5.NewServer(socks5.Config{
		ListenAddr: socksLn.Addr().String(),
		Detector:   det,
		Forwarder:  fwd,
		Hooks: socks5.LifecycleHooks{
			OnConnStart: func(ev socks5.ConnStartEvent) uint64 {
				return tr.Start(tracker.StartEntry{
					Timestamp:  ev.Time,
					ClientAddr: ev.ClientAddr,
					Target:     ev.TargetAddr,
					Protocol:   ev.Protocol,
					Action:     string(ev.Action),
					Pinned:     ev.Pinned,
					SNI:        ev.SNI,
					TLSVersion: ev.TLSVersion,
					WeakTLS:    ev.WeakTLS,
				})
			},
			OnConnEnd: func(id uint64, err error) {
				tr.Finish(id, err)
			},
		},
	})
	go func() { _ = socksSrv.Serve(socksLn) }()
	defer socksSrv.Close()

	webSrv := NewServer(Config{
		ListenAddr:  webLn.Addr().String(),
		Tracker:     tr,
		Detector:    det,
		Forwarder:   fwd,
		SocksServer: socksSrv,
	})
	go func() { _ = webSrv.Serve(webLn) }()
	defer webSrv.Close()

	webBase := "http://" + webLn.Addr().String()
	client := dashboardClient(t, webSrv, webBase)

	dialSocksIPv4 := func(ipStr string, port uint16) net.Conn {
		t.Helper()
		conn, err := net.DialTimeout("tcp", socksSrv.Addr(), 2*time.Second)
		if err != nil {
			t.Fatalf("dial socks: %v", err)
		}
		_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
		var g [2]byte
		_, _ = io.ReadFull(conn, g[:])
		req := append([]byte{0x05, 0x01, 0x00, 0x01}, net.ParseIP(ipStr).To4()...)
		var pb [2]byte
		binary.BigEndian.PutUint16(pb[:], port)
		req = append(req, pb[:]...)
		_, _ = conn.Write(req)
		var rep [10]byte
		if _, err := io.ReadFull(conn, rep[:]); err != nil || rep[1] != 0x00 {
			_ = conn.Close()
			t.Fatalf("socks connect failed: err=%v rep=%x", err, rep)
		}
		return conn
	}

	// 1. 首次发纯 IP (10.88.0.245:443) + 真实 TLS 1.3 ClientHello (SNI=erp.internal.local)
	c1 := dialSocksIPv4("10.88.0.245", 443)
	// 用标准库 tls.Client 写入真实 ClientHello（不等待完整 TLS 服务端响应）
	tlsC := tls.Client(c1, &tls.Config{
		ServerName: "erp.internal.local",
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	_ = tlsC.SetDeadline(time.Now().Add(300 * time.Millisecond))
	_ = tlsC.Handshake()
	_ = tlsC.Close()

	// 2. 通过 /api/connections 验证记录包含 Target=10.88.0.245:443 与 SNI=erp.internal.local
	var firstRec tracker.Record
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(webBase + "/api/connections")
		if err != nil {
			t.Fatalf("GET /api/connections: %v", err)
		}
		var snap ConnectionsResponse
		_ = json.NewDecoder(resp.Body).Decode(&snap)
		_ = resp.Body.Close()
		if len(snap.Connections) >= 1 {
			firstRec = snap.Connections[0]
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if firstRec.Target != "10.88.0.245:443" || firstRec.SNI != "erp.internal.local" || firstRec.TLSVersion != "TLS 1.3" || firstRec.Action != tracker.ActionBurp {
		t.Fatalf("unexpected first TLS record: %+v", firstRec)
	}

	// 3. 模拟前端操作列按钮：按 rec.Target (10.88.0.245:443) 下发强制直连覆盖
	ovBody, _ := json.Marshal(OverrideUpsertRequest{Target: firstRec.Target, Action: socks5.ActionDirect})
	ovResp, err := client.Post(webBase+"/api/overrides", "application/json", bytes.NewReader(ovBody))
	if err != nil {
		t.Fatalf("POST /api/overrides: %v", err)
	}
	_ = ovResp.Body.Close()
	if ovResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/overrides status = %d, want 200", ovResp.StatusCode)
	}

	// 4. 第二次连接 10.88.0.245:443 应直接命中 Direct 覆盖并跳过 200ms Peek 拿到 DIRECT-OK
	hitsBefore := burpHits.Load()
	start := time.Now()
	c2 := dialSocksIPv4("10.88.0.245", 443)
	got := make([]byte, 9)
	if _, err := io.ReadFull(c2, got); err != nil {
		_ = c2.Close()
		t.Fatalf("read direct banner: %v", err)
	}
	elapsed := time.Since(start)
	_ = c2.Close()

	if string(got) != "DIRECT-OK" {
		t.Fatalf("got %q, want DIRECT-OK", got)
	}
	if elapsed >= 120*time.Millisecond {
		t.Fatalf("expected Direct override to skip 200ms peek, took %v", elapsed)
	}
	if burpHits.Load() != hitsBefore {
		t.Fatalf("pinned Direct connection leaked to Burp!")
	}
	recs := tr.List()
	if len(recs) < 2 || !recs[0].Pinned || recs[0].Action != tracker.ActionDirect {
		t.Fatalf("expected latest record Pinned=true Action=Direct, got %+v", recs[0])
	}
}
