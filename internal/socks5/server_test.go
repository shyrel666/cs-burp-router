package socks5

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"cs-burp-router/internal/detector"
	"cs-burp-router/internal/forwarder"
)

// mockBurpServer 模拟本地 Burp Suite HTTP CONNECT 代理，记录收到的 CONNECT 目标和隧道首包并回写响应。
type mockBurpServer struct {
	ln          net.Listener
	mu          sync.Mutex
	connectReqs []string
	payloads    [][]byte
	replyData   []byte
	hitCount    atomic.Int32
}

func startMockBurp(t *testing.T, replyData []byte) *mockBurpServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock burp: %v", err)
	}
	m := &mockBurpServer{
		ln:        ln,
		replyData: replyData,
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			m.hitCount.Add(1)
			go m.handle(conn)
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
	})
	return m
}

func (m *mockBurpServer) Addr() string {
	return m.ln.Addr().String()
}

func (m *mockBurpServer) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		// 非 CONNECT 隧道的直接请求（例如回环直连测试），读取原始报文后直接回复
		return
	}
	if req.Method != http.MethodConnect {
		// 如果收到普通非 CONNECT 请求（例如回环直连绕过隧道），直接回复特殊标识供断言区分
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\ndirect-no-tun"))
		return
	}

	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	// 读取客户端经隧道发来的数据（客户端测试中发送后半关闭写端）
	data, _ := io.ReadAll(br)

	m.mu.Lock()
	m.connectReqs = append(m.connectReqs, req.Host)
	m.payloads = append(m.payloads, data)
	m.mu.Unlock()

	if len(m.replyData) > 0 {
		_, _ = conn.Write(m.replyData)
	}
}

func (m *mockBurpServer) snapshot() (connects []string, payloads [][]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	connects = append([]string(nil), m.connectReqs...)
	payloads = make([][]byte, len(m.payloads))
	for i, p := range m.payloads {
		payloads[i] = append([]byte(nil), p...)
	}
	return connects, payloads
}

// socks5ConnectClient 执行完整的无认证 SOCKS5 CONNECT 握手（支持 IPv4 / IPv6 / Domain）。
func socks5ConnectClient(t *testing.T, socksAddr string, atyp byte, targetHost string, targetPort uint16) (net.Conn, byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", socksAddr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial socks5 %s: %v", socksAddr, err)
	}

	// 1. Greeting: VER=5, NMETHODS=1, METHOD=0x00 (No Auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		t.Fatalf("write greeting: %v", err)
	}
	var greetResp [2]byte
	if _, err := io.ReadFull(conn, greetResp[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read greeting reply: %v", err)
	}
	if greetResp != [2]byte{0x05, 0x00} {
		_ = conn.Close()
		t.Fatalf("unexpected greeting reply: %x", greetResp)
	}

	// 2. CONNECT Request
	req := []byte{0x05, 0x01, 0x00, atyp}
	switch atyp {
	case atypIPv4:
		ip := net.ParseIP(targetHost).To4()
		if ip == nil {
			_ = conn.Close()
			t.Fatalf("invalid IPv4 %q", targetHost)
		}
		req = append(req, ip...)
	case atypIPv6:
		ip := net.ParseIP(targetHost).To16()
		if ip == nil {
			_ = conn.Close()
			t.Fatalf("invalid IPv6 %q", targetHost)
		}
		req = append(req, ip...)
	case atypDomain:
		req = append(req, byte(len(targetHost)))
		req = append(req, []byte(targetHost)...)
	default:
		_ = conn.Close()
		t.Fatalf("unsupported test atyp 0x%02x", atyp)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], targetPort)
	req = append(req, portBytes[:]...)

	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		t.Fatalf("write connect request: %v", err)
	}

	var reply [10]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read connect reply: %v", err)
	}
	if reply[0] != 0x05 {
		_ = conn.Close()
		t.Fatalf("unexpected reply version: 0x%02x", reply[0])
	}
	return conn, reply[1]
}

func startTestSOCKS5Server(t *testing.T, cfg Config) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}
	cfg.ListenAddr = ln.Addr().String()
	srv := NewServer(cfg)
	go func() {
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Close()
	})
	return srv
}

func TestDirectRoutesReportDialFailureBeforeSuccess(t *testing.T) {
	const port = 39857
	const endpoint = "127.0.0.1:39857"
	for _, tc := range []struct {
		name   string
		config Config
	}{
		{"port whitelist", Config{Detector: detector.New(detector.Config{DirectPorts: []uint16{port}})}},
		{"global bypass", Config{BypassAll: true}},
		{"local endpoint", Config{BypassAddrs: []string{endpoint}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.config.Forwarder = forwarder.New(forwarder.Config{
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					return nil, syscall.ECONNREFUSED
				},
			})
			srv := startTestSOCKS5Server(t, tc.config)
			conn, reply := socks5ConnectClient(t, srv.Addr(), atypIPv4, "127.0.0.1", port)
			defer conn.Close()
			if reply != repConnectionRefused {
				t.Fatalf("reply = 0x%02x, want connection refused", reply)
			}
		})
	}
}

func TestRoutingUpdatePublishesWholeConfiguration(t *testing.T) {
	srv := NewServer(Config{})
	defer srv.Close()
	addrA, addrB := "127.0.0.1:8001", "127.0.0.1:8002"
	portsA, portsB := []uint16{8001}, []uint16{8002}
	bypassA, bypassB := true, false
	configA := RoutingUpdate{BurpAddr: &addrA, DirectPorts: &portsA, BypassAll: &bypassA}
	configB := RoutingUpdate{BurpAddr: &addrB, DirectPorts: &portsB, BypassAll: &bypassB}
	srv.UpdateRoutingConfig(configA)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			srv.UpdateRoutingConfig(configB)
			srv.UpdateRoutingConfig(configA)
		}
	}()
	for range 200 {
		addr, bypass, directPort := srv.routeForPort(8001)
		switch {
		case addr == addrA && bypass && directPort:
		case addr == addrB && !bypass && !directPort:
		default:
			t.Errorf("mixed routing settings: %s, bypass=%v, direct=%v", addr, bypass, directPort)
		}
	}
	<-done
}

// 验收测试用例 1：客户端发 HTTP GET 请求 → 验证被识别为 HTTP 并转发到模拟 Burp 服务端（覆盖 Domain / IPv4 / IPv6）。
func TestAcceptanceCase1_HTTPGetForwardedToBurp(t *testing.T) {
	wantBurpResp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nhello-from-burp")
	mockBurp := startMockBurp(t, wantBurpResp)

	decisionCh := make(chan DecisionEvent, 4)
	srv := startTestSOCKS5Server(t, Config{
		Detector: detector.NewDefault(),
		Forwarder: forwarder.New(forwarder.Config{
			BurpAddr: mockBurp.Addr(),
		}),
		OnDecision: func(ev DecisionEvent) {
			decisionCh <- ev
		},
	})

	cases := []struct {
		name     string
		atyp     byte
		host     string
		port     uint16
		wantAddr string
	}{
		{name: "Domain", atyp: atypDomain, host: "erp.corp.internal", port: 8081, wantAddr: "erp.corp.internal:8081"},
		{name: "IPv4", atyp: atypIPv4, host: "10.20.30.40", port: 80, wantAddr: "10.20.30.40:80"},
		{name: "IPv6", atyp: atypIPv6, host: "2001:db8::88", port: 8080, wantAddr: "[2001:db8::88]:8080"},
	}

	for idx, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, rep := socks5ConnectClient(t, srv.Addr(), tc.atyp, tc.host, tc.port)
			defer conn.Close()
			if rep != repSuccess {
				t.Fatalf("expected SOCKS5 repSuccess (0x00), got 0x%02x", rep)
			}

			httpGet := []byte(fmt.Sprintf("GET /v1/orders?id=%d HTTP/1.1\r\nHost: %s\r\nUser-Agent: cs-client/1.0\r\n\r\n", idx, tc.wantAddr))
			if _, err := conn.Write(httpGet); err != nil {
				t.Fatalf("write HTTP GET: %v", err)
			}
			_ = conn.(*net.TCPConn).CloseWrite()

			gotResp, err := io.ReadAll(conn)
			if err != nil {
				t.Fatalf("read HTTP response: %v", err)
			}
			if !bytes.Equal(gotResp, wantBurpResp) {
				t.Fatalf("response mismatch: got %q, want %q", gotResp, wantBurpResp)
			}

			select {
			case ev := <-decisionCh:
				if ev.Protocol != detector.ProtoHTTP {
					t.Fatalf("got protocol %q, want %q", ev.Protocol, detector.ProtoHTTP)
				}
				if ev.Action != ActionBurp {
					t.Fatalf("got action %q, want %q", ev.Action, ActionBurp)
				}
				if ev.TargetAddr != tc.wantAddr {
					t.Fatalf("got target %q, want %q", ev.TargetAddr, tc.wantAddr)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for routing decision event")
			}

			connects, payloads := mockBurp.snapshot()
			if len(connects) != idx+1 {
				t.Fatalf("expected %d Burp CONNECT requests, got %d", idx+1, len(connects))
			}
			if connects[idx] != tc.wantAddr {
				t.Fatalf("Burp CONNECT target = %q, want %q", connects[idx], tc.wantAddr)
			}
			if !bytes.Equal(payloads[idx], httpGet) {
				t.Fatalf("Burp received incomplete/corrupted HTTP GET:\ngot:  %q\nwant: %q", payloads[idx], httpGet)
			}
		})
	}
}

// 验收测试用例 2：客户端发 TLS ClientHello (0x16 0x03 0x01 ...) → 验证被识别为 TLS/HTTPS 并通过 CONNECT 转发到模拟 Burp 服务端。
func TestAcceptanceCase2_TLSClientHelloForwardedToBurp(t *testing.T) {
	// 模拟 TLS ServerHello 响应
	mockServerHello := []byte{0x16, 0x03, 0x03, 0x00, 0x0a, 0x02, 0x00, 0x00, 0x06, 0x03, 0x03, 0x99, 0x88, 0x77, 0x66}
	mockBurp := startMockBurp(t, mockServerHello)

	decisionCh := make(chan DecisionEvent, 1)
	srv := startTestSOCKS5Server(t, Config{
		Detector: detector.NewDefault(),
		Forwarder: forwarder.New(forwarder.Config{
			BurpAddr: mockBurp.Addr(),
		}),
		OnDecision: func(ev DecisionEvent) {
			decisionCh <- ev
		},
	})

	conn, rep := socks5ConnectClient(t, srv.Addr(), atypDomain, "secure.trade.local", 443)
	defer conn.Close()
	if rep != repSuccess {
		t.Fatalf("expected SOCKS5 repSuccess, got 0x%02x", rep)
	}

	// 构造 TLS ClientHello 报文（0x16 0x03 0x01 ...，长度大于 Peek 8 字节以同时验证零字节丢失）
	clientHello := make([]byte, 128)
	copy(clientHello, []byte{
		0x16, 0x03, 0x01, 0x00, 0x7b, // TLS Record Layer: Handshake (22), TLS 1.0 record version (0x0301)
		0x01, 0x00, 0x00, 0x77, // Handshake Type: ClientHello (1)
		0x03, 0x03, // Client Version: TLS 1.2
	})
	for i := 11; i < len(clientHello); i++ {
		clientHello[i] = byte(i & 0xff)
	}

	if _, err := conn.Write(clientHello); err != nil {
		t.Fatalf("write TLS ClientHello: %v", err)
	}
	_ = conn.(*net.TCPConn).CloseWrite()

	gotServerHello, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read TLS ServerHello: %v", err)
	}
	if !bytes.Equal(gotServerHello, mockServerHello) {
		t.Fatalf("TLS ServerHello mismatch: got %x, want %x", gotServerHello, mockServerHello)
	}

	select {
	case ev := <-decisionCh:
		if ev.Protocol != detector.ProtoTLS {
			t.Fatalf("got protocol %q, want %q", ev.Protocol, detector.ProtoTLS)
		}
		if ev.Action != ActionBurp {
			t.Fatalf("got action %q, want %q", ev.Action, ActionBurp)
		}
		if ev.TargetAddr != "secure.trade.local:443" {
			t.Fatalf("got target %q, want secure.trade.local:443", ev.TargetAddr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for TLS decision event")
	}

	connects, payloads := mockBurp.snapshot()
	if len(connects) != 1 || connects[0] != "secure.trade.local:443" {
		t.Fatalf("unexpected Burp CONNECT records: %v", connects)
	}
	if !bytes.Equal(payloads[0], clientHello) {
		t.Fatalf("TLS ClientHello lost/corrupted bytes: got %d bytes, want %d bytes", len(payloads[0]), len(clientHello))
	}
}

// 验收测试用例 3：模拟 MySQL（服务端先发 Banner，客户端等待）在白名单端口（3306）和非白名单端口（13306）两种情况
// 验证均在 250ms 内成功直连拿到服务端 Banner，且双向通信无死锁、无超时、无字节丢失。
func TestAcceptanceCase3_MySQLServerSpeaksFirstWhitelistAndFallback(t *testing.T) {
	// 构造真实感 MySQL Initial Handshake Packet (Server Greeting Banner)
	mysqlBanner := append(
		[]byte{0x4a, 0x00, 0x00, 0x00, 0x0a},
		[]byte("8.0.36-MySQL-Community-Server\x00auth-plugin-salt-data-1234567890\x00")...,
	)
	clientAuthPacket := []byte("MYSQL_CLIENT_AUTH_HANDSHAKE_RESPONSE_41")
	mysqlOKPacket := []byte{0x07, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}

	// 启动模拟 MySQL 服务端（连接建立后立即主动发送 Banner，随后读取客户端认证包并回 OK 包）
	mysqlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock mysql: %v", err)
	}
	defer mysqlLn.Close()

	go func() {
		for {
			conn, err := mysqlLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				// Server-Speaks-First：立即发送 MySQL Greeting Banner
				if _, err := c.Write(mysqlBanner); err != nil {
					return
				}
				// 读取客户端后续发来的认证包，验证双向通道畅通无丢字节
				buf := make([]byte, len(clientAuthPacket))
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				if bytes.Equal(buf, clientAuthPacket) {
					_, _ = c.Write(mysqlOKPacket)
				}
			}(conn)
		}
	}()

	mockBurp := startMockBurp(t, nil)
	actualMySQLAddr := mysqlLn.Addr().String()

	// 使用标准 Dialer 并在测试中把模拟的目标端口 (3306 / 13306) 映射到临时监听的 mockMySQL，
	// 避免宿主开发机已安装本地 MySQL 占用 3306 端口导致端口冲突，同时完整覆盖 3306 默认白名单与 13306 非白名单路径。
	baseDialer := &net.Dialer{Timeout: 3 * time.Second}
	fwd := forwarder.New(forwarder.Config{
		BurpAddr: mockBurp.Addr(),
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == "127.0.0.1:3306" || address == "127.0.0.1:13306" {
				return baseDialer.DialContext(ctx, network, actualMySQLAddr)
			}
			return baseDialer.DialContext(ctx, network, address)
		},
	})

	decisionCh := make(chan DecisionEvent, 4)
	srv := startTestSOCKS5Server(t, Config{
		Detector:  detector.NewDefault(),
		Forwarder: fwd,
		OnDecision: func(ev DecisionEvent) {
			decisionCh <- ev
		},
	})

	scenarios := []struct {
		name       string
		port       uint16
		wantReason string
	}{
		{
			name:       "WhitelistedPort_3306",
			port:       3306,
			wantReason: "port-whitelist",
		},
		{
			name:       "NonWhitelistedPort_13306",
			port:       13306,
			wantReason: "peek-unknown",
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			start := time.Now()

			conn, rep := socks5ConnectClient(t, srv.Addr(), atypIPv4, "127.0.0.1", sc.port)
			defer conn.Close()
			if rep != repSuccess {
				t.Fatalf("SOCKS5 connect to port %d failed with rep 0x%02x", sc.port, rep)
			}

			if err := conn.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
				t.Fatalf("set client deadline: %v", err)
			}

			// 客户端不发任何字节，直接等待读取 MySQL 服务端 Banner
			gotBanner := make([]byte, len(mysqlBanner))
			if _, err := io.ReadFull(conn, gotBanner); err != nil {
				t.Fatalf("read MySQL banner on port %d failed: %v", sc.port, err)
			}
			bannerElapsed := time.Since(start)

			if bannerElapsed >= 250*time.Millisecond {
				t.Fatalf("port %d took %v to receive MySQL banner, want < 250ms", sc.port, bannerElapsed)
			}
			if !bytes.Equal(gotBanner, mysqlBanner) {
				t.Fatalf("MySQL banner corrupted on port %d: got %x, want %x", sc.port, gotBanner, mysqlBanner)
			}

			// 继续发送客户端握手响应并读取 MySQL OK 包，确认后续双向数据流完全正常
			if _, err := conn.Write(clientAuthPacket); err != nil {
				t.Fatalf("write MySQL client auth packet: %v", err)
			}
			gotOK := make([]byte, len(mysqlOKPacket))
			if _, err := io.ReadFull(conn, gotOK); err != nil {
				t.Fatalf("read MySQL OK packet: %v", err)
			}
			if !bytes.Equal(gotOK, mysqlOKPacket) {
				t.Fatalf("MySQL OK packet mismatch: got %x, want %x", gotOK, mysqlOKPacket)
			}

			select {
			case ev := <-decisionCh:
				if ev.Action != ActionDirect {
					t.Fatalf("port %d got action %q, want %q", sc.port, ev.Action, ActionDirect)
				}
				if ev.Protocol != detector.ProtoUnknown {
					t.Fatalf("port %d got protocol %q, want %q", sc.port, ev.Protocol, detector.ProtoUnknown)
				}
				if ev.Reason != sc.wantReason {
					t.Fatalf("port %d got reason %q, want %q", sc.port, ev.Reason, sc.wantReason)
				}
			case <-time.After(1 * time.Second):
				t.Fatalf("port %d missing decision event", sc.port)
			}
		})
	}

	if hits := mockBurp.hitCount.Load(); hits != 0 {
		t.Fatalf("MySQL traffic must never touch Burp, but mockBurp got %d connections", hits)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// 验证回环流量保护：指向 Burp 自身地址（含 IPv4 / localhost / IPv6）的请求不得进入 Burp CONNECT 隧道；
// 指向 SOCKS5 自身监听地址的请求必须被拒绝 (0x02)。
func TestLoopbackExclusionAndProtocolErrors(t *testing.T) {
	mockBurp := startMockBurp(t, nil)
	_, burpPortStr, err := net.SplitHostPort(mockBurp.Addr())
	if err != nil {
		t.Fatalf("split burp addr: %v", err)
	}
	var burpPort uint16
	_, _ = fmt.Sscanf(burpPortStr, "%d", &burpPort)

	var logBuf syncBuffer
	decisionCh := make(chan DecisionEvent, 4)
	srv := startTestSOCKS5Server(t, Config{
		Detector: detector.NewDefault(),
		Forwarder: forwarder.New(forwarder.Config{
			BurpAddr: mockBurp.Addr(),
		}),
		Logger: log.New(&logBuf, "", 0),
		OnDecision: func(ev DecisionEvent) {
			decisionCh <- ev
		},
	})

	// 1. 请求目标为 Burp 自身地址 (localhost:<burpPort>)，即使发送 HTTP GET 也必须走 Direct 绕过 CONNECT 隧道
	conn, rep := socks5ConnectClient(t, srv.Addr(), atypDomain, "localhost", burpPort)
	if rep != repSuccess {
		t.Fatalf("expected repSuccess for burp direct bypass, got 0x%02x", rep)
	}
	_, _ = conn.Write([]byte("GET /cert HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	rawResp, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil {
		t.Fatalf("read direct burp response: %v", err)
	}
	if !bytes.Contains(rawResp, []byte("direct-no-tun")) {
		t.Fatalf("expected direct connection to mockBurp without CONNECT wrapper, got %q", rawResp)
	}

	ev := <-decisionCh
	if ev.Action != ActionDirect || ev.Reason != "loopback-bypass" {
		t.Fatalf("expected ActionDirect/loopback-bypass, got action=%q reason=%q", ev.Action, ev.Reason)
	}
	connects, _ := mockBurp.snapshot()
	if len(connects) != 0 {
		t.Fatalf("expected 0 Burp CONNECT tunnel calls on loopback bypass, got %v", connects)
	}

	// 2. 请求目标为 SOCKS5 自身监听端口：必须拒绝连接 (repNotAllowed = 0x02)
	_, socksPortStr, _ := net.SplitHostPort(srv.Addr())
	var socksPort uint16
	_, _ = fmt.Sscanf(socksPortStr, "%d", &socksPort)

	selfConn, selfRep := socks5ConnectClient(t, srv.Addr(), atypIPv4, "127.0.0.1", socksPort)
	_ = selfConn.Close()
	if selfRep != repNotAllowed {
		t.Fatalf("expected repNotAllowed (0x02) when connecting SOCKS5 to itself, got 0x%02x", selfRep)
	}

	// 3. 不支持的 SOCKS5 命令 (UDP ASSOCIATE = 0x03) 应返回 0x07 且静默不打印刷屏错误日志
	badCmdConn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial socks5: %v", err)
	}
	_, _ = badCmdConn.Write([]byte{0x05, 0x01, 0x00})
	var g [2]byte
	_, _ = io.ReadFull(badCmdConn, g[:])
	_, _ = badCmdConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50})
	var r [10]byte
	if _, err := io.ReadFull(badCmdConn, r[:]); err != nil {
		_ = badCmdConn.Close()
		t.Fatalf("read cmd error reply: %v", err)
	}
	_ = badCmdConn.Close()
	if r[1] != repCmdNotSupported {
		t.Fatalf("expected repCmdNotSupported (0x07), got 0x%02x", r[1])
	}
	time.Sleep(20 * time.Millisecond)
	if strings.Contains(logBuf.String(), "0x03") {
		t.Fatalf("expected 0x03 UDP ASSOCIATE probe to be suppressed from error logs, got: %q", logBuf.String())
	}

	// 4. 其他不支持的 SOCKS5 命令 (BIND = 0x02) 仍返回 0x07 并正常记录诊断日志
	bindConn, err := net.Dial("tcp", srv.Addr())
	if err != nil {
		t.Fatalf("dial socks5 for BIND: %v", err)
	}
	defer bindConn.Close()
	_, _ = bindConn.Write([]byte{0x05, 0x01, 0x00})
	_, _ = io.ReadFull(bindConn, g[:])
	_, _ = bindConn.Write([]byte{0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50})
	if _, err := io.ReadFull(bindConn, r[:]); err != nil {
		t.Fatalf("read BIND error reply: %v", err)
	}
	if r[1] != repCmdNotSupported {
		t.Fatalf("expected repCmdNotSupported (0x07) for BIND, got 0x%02x", r[1])
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && !strings.Contains(logBuf.String(), "0x02") {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(logBuf.String(), "unsupported socks5 command: 0x02") {
		t.Fatalf("expected BIND 0x02 error to be logged, got: %q", logBuf.String())
	}
}
