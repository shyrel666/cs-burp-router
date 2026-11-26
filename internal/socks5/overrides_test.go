package socks5

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"cs-burp-router/internal/detector"
	"cs-burp-router/internal/forwarder"
)

func TestOverrideNormalizationAndMatching(t *testing.T) {
	store := NewOverrideStore()

	// 规范化验证
	r1, err := store.Set("Example.COM.:443", ActionDirect)
	if err != nil || r1.Target != "example.com:443" || r1.Action != ActionDirect {
		t.Fatalf("unexpected rule1: %+v err=%v", r1, err)
	}
	r2, err := store.Set("EXAMPLE.com", ActionBurp)
	if err != nil || r2.Target != "example.com" || r2.Action != ActionBurp {
		t.Fatalf("unexpected rule2: %+v err=%v", r2, err)
	}
	r3, err := store.Set("[2001:0db8::0001]:8443", ActionDirect)
	if err != nil || r3.Target != "[2001:db8::1]:8443" {
		t.Fatalf("unexpected ipv6 rule: %+v err=%v", r3, err)
	}
	r4, err := store.Set("2001:0db8::0002", ActionBurp)
	if err != nil || r4.Target != "2001:db8::2" {
		t.Fatalf("unexpected bare ipv6 rule: %+v err=%v", r4, err)
	}

	// 精确 host:port 优先于按 host 匹配
	if act, ok := store.Match("example.com", 443); !ok || act != ActionDirect {
		t.Fatalf("exact match failed: act=%q ok=%v, want Direct", act, ok)
	}
	if act, ok := store.Match("example.com", 8080); !ok || act != ActionBurp {
		t.Fatalf("host fallback match failed: act=%q ok=%v, want Burp", act, ok)
	}
	if act, ok := store.Match("2001:db8::1", 8443); !ok || act != ActionDirect {
		t.Fatalf("ipv6 exact match failed: act=%q ok=%v", act, ok)
	}
	if act, ok := store.Match("2001:db8::2", 9000); !ok || act != ActionBurp {
		t.Fatalf("ipv6 host match failed: act=%q ok=%v", act, ok)
	}

	// 非法输入校验
	for _, badTarget := range []string{"", "   ", "bad host:80", "example.com:0", "example.com:70000", "example.com:abc", "a/b:80"} {
		if _, err := store.Set(badTarget, ActionDirect); err == nil {
			t.Fatalf("expected error for invalid target %q", badTarget)
		}
	}
	if _, err := store.Set("10.0.0.1:80", RouteAction("Invalid")); err == nil {
		t.Fatal("expected error for invalid action")
	}

	// 删除与清空
	existed, err := store.Delete("EXAMPLE.COM:443")
	if err != nil || !existed {
		t.Fatalf("Delete existing rule failed: existed=%v err=%v", existed, err)
	}
	if act, ok := store.Match("example.com", 443); !ok || act != ActionBurp {
		t.Fatalf("after deleting exact rule, expected host fallback Burp, got act=%q ok=%v", act, ok)
	}
	store.Clear()
	if len(store.List()) != 0 {
		t.Fatalf("expected empty overrides after Clear, got %v", store.List())
	}
}

// 验证覆盖规则严格遵循优先级：
// 自回环/自身排除 > BypassAll 全局直连 > 目标覆盖规则（Pin） > DirectPorts 端口白名单 > 200ms 协议窥探
func TestOverrideRoutingPriority(t *testing.T) {
	burpReply := []byte("HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nvia-burp")
	mockBurp := startMockBurp(t, burpReply)

	// 启动模拟服务端：
	// 1) Server-Speaks-First 直连服务（用于验证 Direct 覆盖跳过 200ms Peek）
	ssfBanner := []byte("BANNER-IMMEDIATE-OK\r\n")
	ssfLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ssf mock: %v", err)
	}
	defer ssfLn.Close()
	go func() {
		for {
			c, err := ssfLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write(ssfBanner)
			}(c)
		}
	}()

	// 2) HTTP 直连服务（用于验证 BypassAll 优先于 Burp 覆盖规则）
	directHTTPResp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nvia-direct")
	directHTTPLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen direct http mock: %v", err)
	}
	defer directHTTPLn.Close()
	go func() {
		for {
			c, err := directHTTPLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 512)
				_, _ = conn.Read(buf)
				_, _ = conn.Write(directHTTPResp)
			}(c)
		}
	}()

	baseDialer := &net.Dialer{Timeout: 2 * time.Second}
	fwd := forwarder.New(forwarder.Config{
		BurpAddr: mockBurp.Addr(),
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			switch address {
			case "10.99.0.1:13306":
				return baseDialer.DialContext(ctx, network, ssfLn.Addr().String())
			case "10.99.0.2:3306":
				return baseDialer.DialContext(ctx, network, directHTTPLn.Addr().String())
			default:
				return baseDialer.DialContext(ctx, network, address)
			}
		},
	})

	decisionCh := make(chan DecisionEvent, 8)
	startCh := make(chan ConnStartEvent, 8)
	srv := startTestSOCKS5Server(t, Config{
		Detector:  detector.NewDefault(), // 默认包含 3306 端口白名单，200ms PeekTimeout
		Forwarder: fwd,
		OnDecision: func(ev DecisionEvent) {
			decisionCh <- ev
		},
		Hooks: LifecycleHooks{
			OnConnStart: func(ev ConnStartEvent) uint64 {
				startCh <- ev
				return 1
			},
		},
	})

	// 场景 1：Direct 覆盖跳过 200ms Peek（非白名单端口 13306，Server-Speaks-First 应在 <100ms 拿到 Banner）
	t.Run("DirectOverrideSkips200msPeek", func(t *testing.T) {
		if _, err := srv.SetOverride("10.99.0.1:13306", ActionDirect); err != nil {
			t.Fatalf("SetOverride Direct: %v", err)
		}
		defer srv.ClearOverrides()

		start := time.Now()
		conn, rep := socks5ConnectClient(t, srv.Addr(), atypIPv4, "10.99.0.1", 13306)
		defer conn.Close()
		if rep != repSuccess {
			t.Fatalf("rep = 0x%02x, want repSuccess", rep)
		}

		got := make([]byte, len(ssfBanner))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read ssf banner: %v", err)
		}
		elapsed := time.Since(start)
		if !bytes.Equal(got, ssfBanner) {
			t.Fatalf("banner = %q, want %q", got, ssfBanner)
		}
		if elapsed >= 120*time.Millisecond {
			t.Fatalf("Direct override did not skip 200ms peek, took %v", elapsed)
		}

		ev := <-decisionCh
		stEv := <-startCh
		if ev.Action != ActionDirect || !ev.Pinned || ev.Reason != "override-direct" {
			t.Fatalf("unexpected decision event: %+v", ev)
		}
		if !stEv.Pinned || stEv.Protocol != "Pinned" {
			t.Fatalf("unexpected start event: %+v", stEv)
		}
		if mockBurp.hitCount.Load() != 0 {
			t.Fatalf("Direct override touched Burp: hits=%d", mockBurp.hitCount.Load())
		}
	})

	// 场景 2：Burp 覆盖突破数据库端口白名单（3306 在 DirectPorts 中，但按 host 或 host:port 覆盖为 Burp 后进入 Burp）
	t.Run("BurpOverrideBeatsDirectPortWhitelist", func(t *testing.T) {
		if _, err := srv.SetOverride("10.99.0.2", ActionBurp); err != nil {
			t.Fatalf("SetOverride Burp by host: %v", err)
		}
		defer srv.ClearOverrides()

		conn, rep := socks5ConnectClient(t, srv.Addr(), atypIPv4, "10.99.0.2", 3306)
		defer conn.Close()
		if rep != repSuccess {
			t.Fatalf("rep = 0x%02x, want repSuccess", rep)
		}
		reqPayload := []byte("GET /db-admin HTTP/1.1\r\nHost: 10.99.0.2:3306\r\n\r\n")
		if _, err := conn.Write(reqPayload); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		_ = conn.(*net.TCPConn).CloseWrite()

		gotResp, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("read burp resp: %v", err)
		}
		if !bytes.Equal(gotResp, burpReply) {
			t.Fatalf("got %q, want Burp reply %q", gotResp, burpReply)
		}

		ev := <-decisionCh
		stEv := <-startCh
		if ev.Action != ActionBurp || !ev.Pinned || ev.Reason != "override-burp" {
			t.Fatalf("unexpected decision event: %+v", ev)
		}
		if !stEv.Pinned || stEv.Action != ActionBurp {
			t.Fatalf("unexpected start event: %+v", stEv)
		}
		connects, payloads := mockBurp.snapshot()
		if len(connects) != 1 || connects[0] != "10.99.0.2:3306" || !bytes.Equal(payloads[0], reqPayload) {
			t.Fatalf("unexpected mockBurp records: connects=%v payloads=%q", connects, payloads)
		}
	})

	// 场景 3：BypassAll 全局直连优先于目标覆盖规则（即使已覆盖 10.99.0.2:3306 -> Burp，开启 BypassAll 仍直连）
	t.Run("BypassAllBeatsOverrideRule", func(t *testing.T) {
		if _, err := srv.SetOverride("10.99.0.2:3306", ActionBurp); err != nil {
			t.Fatalf("SetOverride Burp: %v", err)
		}
		defer srv.ClearOverrides()

		srv.SetBypassAll(true)
		defer srv.SetBypassAll(false)

		burpHitsBefore := mockBurp.hitCount.Load()

		conn, rep := socks5ConnectClient(t, srv.Addr(), atypIPv4, "10.99.0.2", 3306)
		defer conn.Close()
		if rep != repSuccess {
			t.Fatalf("rep = 0x%02x, want repSuccess", rep)
		}
		_, _ = conn.Write([]byte("GET /bypass HTTP/1.1\r\nHost: 10.99.0.2:3306\r\n\r\n"))
		gotResp, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("read direct resp: %v", err)
		}
		if !bytes.Equal(gotResp, directHTTPResp) {
			t.Fatalf("got %q, want direct HTTP reply %q", gotResp, directHTTPResp)
		}

		ev := <-decisionCh
		stEv := <-startCh
		if ev.Action != ActionDirect || ev.Pinned || ev.Reason != "bypass-all" {
			t.Fatalf("expected BypassAll to override pin, got %+v", ev)
		}
		if stEv.Pinned {
			t.Fatalf("expected Pinned=false when BypassAll wins, got %+v", stEv)
		}
		if mockBurp.hitCount.Load() != burpHitsBefore {
			t.Fatalf("BypassAll leaked connection to Burp!")
		}
	})

	// 场景 4：自回环/Burp 自身排除优先于覆盖规则
	t.Run("LoopbackBypassBeatsOverrideRule", func(t *testing.T) {
		_, burpPortStr, _ := net.SplitHostPort(mockBurp.Addr())
		var burpPort uint16
		_, _ = fmt.Sscanf(burpPortStr, "%d", &burpPort)

		if _, err := srv.SetOverride(mockBurp.Addr(), ActionBurp); err != nil {
			t.Fatalf("SetOverride burp addr: %v", err)
		}
		defer srv.ClearOverrides()

		conn, rep := socks5ConnectClient(t, srv.Addr(), atypIPv4, "127.0.0.1", burpPort)
		defer conn.Close()
		if rep != repSuccess {
			t.Fatalf("rep = 0x%02x, want repSuccess", rep)
		}
		_, _ = conn.Write([]byte("GET /cert HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
		rawResp, err := io.ReadAll(conn)
		if err != nil {
			t.Fatalf("read loopback resp: %v", err)
		}
		if !bytes.Contains(rawResp, []byte("direct-no-tun")) {
			t.Fatalf("expected direct-no-tun on loopback bypass, got %q", rawResp)
		}

		ev := <-decisionCh
		<-startCh
		if ev.Action != ActionDirect || ev.Reason != "loopback-bypass" || ev.Pinned {
			t.Fatalf("expected loopback-bypass to beat override, got %+v", ev)
		}
	})
}

func TestServerOverridesConcurrencyRace(t *testing.T) {
	srv := NewServer(Config{})
	defer srv.Close()

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				target := fmt.Sprintf("10.0.%d.%d:443", id, j%5)
				if j%3 == 0 {
					_, _ = srv.SetOverride(target, ActionDirect)
				} else if j%3 == 1 {
					_, _ = srv.SetOverride(target, ActionBurp)
				} else {
					_, _ = srv.DeleteOverride(target)
				}
				_, _ = srv.MatchOverride(fmt.Sprintf("10.0.%d.%d", id, j%5), 443)
				_ = srv.Overrides()
			}
		}(i)
	}
	wg.Wait()
}
