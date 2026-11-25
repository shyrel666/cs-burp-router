package detector

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func newTCPPair(t *testing.T) (client net.Conn, server net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()

	type acceptRes struct {
		conn net.Conn
		err  error
	}
	ch := make(chan acceptRes, 1)
	go func() {
		c, err := ln.Accept()
		ch <- acceptRes{conn: c, err: err}
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}
	res := <-ch
	if res.err != nil {
		_ = clientConn.Close()
		t.Fatalf("accept tcp: %v", res.err)
	}
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = res.conn.Close()
	})
	return clientConn, res.conn
}

func TestDetectHTTPMethodsAndNoByteLoss(t *testing.T) {
	methods := []string{
		"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\ntest",
		"PUT /items/1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"DELETE /items/1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"HEAD /status HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"PATCH /items/1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
	}

	det := NewDefault()
	for _, rawReq := range methods {
		t.Run(rawReq[:4], func(t *testing.T) {
			client, server := newTCPPair(t)

			payload := []byte(rawReq)
			if _, err := client.Write(payload); err != nil {
				t.Fatalf("client write: %v", err)
			}
			_ = client.(*net.TCPConn).CloseWrite()

			res, err := det.Detect(server, 8088)
			if err != nil {
				t.Fatalf("Detect error: %v", err)
			}
			if res.Protocol != ProtoHTTP {
				t.Fatalf("got protocol %q, want %q", res.Protocol, ProtoHTTP)
			}
			if res.FastPath {
				t.Fatalf("expected FastPath=false on port 8088")
			}

			rest, err := io.ReadAll(server)
			if err != nil {
				t.Fatalf("read remaining bytes: %v", err)
			}
			reconstructed := append(append([]byte(nil), res.Buffered...), rest...)
			if !bytes.Equal(reconstructed, payload) {
				t.Fatalf("byte loss or corruption: got %q, want %q", reconstructed, payload)
			}
		})
	}
}

func TestDetectTLSClientHello(t *testing.T) {
	det := NewDefault()
	client, server := newTCPPair(t)

	// 构造模拟 TLS 1.0/1.2 ClientHello 记录头 (0x16 0x03 0x01 ...)
	clientHello := []byte{
		0x16, 0x03, 0x01, 0x00, 0x10,
		0x01, 0x00, 0x00, 0x0c, 0x03, 0x03,
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44,
	}
	if _, err := client.Write(clientHello); err != nil {
		t.Fatalf("write tls client hello: %v", err)
	}
	_ = client.(*net.TCPConn).CloseWrite()

	res, err := det.Detect(server, 8443)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if res.Protocol != ProtoTLS {
		t.Fatalf("got protocol %q, want %q", res.Protocol, ProtoTLS)
	}
	if res.FastPath {
		t.Fatalf("expected FastPath=false")
	}

	rest, err := io.ReadAll(server)
	if err != nil {
		t.Fatalf("read remaining: %v", err)
	}
	reconstructed := append(append([]byte(nil), res.Buffered...), rest...)
	if !bytes.Equal(reconstructed, clientHello) {
		t.Fatalf("TLS ClientHello mismatch: got %x, want %x", reconstructed, clientHello)
	}
}

func TestDetectDirectPortWhitelistSkipsPeek(t *testing.T) {
	det := NewDefault()

	for _, port := range DefaultDirectPorts() {
		client, server := newTCPPair(t)
		_ = client // 客户端保持静默，模拟 Server-Speaks-First

		start := time.Now()
		res, err := det.Detect(server, port)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("port %d Detect error: %v", port, err)
		}
		if !res.FastPath {
			t.Fatalf("port %d expected FastPath=true", port)
		}
		if res.Protocol != ProtoUnknown {
			t.Fatalf("port %d got protocol %q, want %q", port, res.Protocol, ProtoUnknown)
		}
		if len(res.Buffered) != 0 {
			t.Fatalf("port %d expected empty Buffered, got %d bytes", port, len(res.Buffered))
		}
		if elapsed > 50*time.Millisecond {
			t.Fatalf("port %d whitelist did not skip peek, took %v", port, elapsed)
		}
	}
}

func TestDetectServerSpeaksFirstTimeoutAndClearDeadline(t *testing.T) {
	det := NewDefault()
	client, server := newTCPPair(t)

	start := time.Now()
	res, err := det.Detect(server, 13306)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Detect on silent client returned error: %v", err)
	}
	if res.Protocol != ProtoUnknown {
		t.Fatalf("got protocol %q, want %q", res.Protocol, ProtoUnknown)
	}
	if res.FastPath {
		t.Fatalf("expected FastPath=false on port 13306")
	}
	if len(res.Buffered) != 0 {
		t.Fatalf("expected 0 buffered bytes, got %d", len(res.Buffered))
	}
	if elapsed < 180*time.Millisecond || elapsed > 250*time.Millisecond {
		t.Fatalf("unexpected peek timeout duration: %v (want ~200ms, <250ms)", elapsed)
	}

	// 验证读取超时已被清除：超过 200ms 后客户端再发数据，服务端仍能正常读取而不超时。
	time.Sleep(50 * time.Millisecond)
	laterMsg := []byte("mysql-auth-response")
	if _, err := client.Write(laterMsg); err != nil {
		t.Fatalf("write later message: %v", err)
	}
	got := make([]byte, len(laterMsg))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("subsequent read failed (deadline not cleared?): %v", err)
	}
	if !bytes.Equal(got, laterMsg) {
		t.Fatalf("subsequent read mismatch: got %q, want %q", got, laterMsg)
	}
}

func TestDetectShortUnknownPacketPreservesBytes(t *testing.T) {
	det := NewDefault()
	client, server := newTCPPair(t)

	// 发送不足 8 字节的短报文并等待服务端响应（不关闭写端）
	shortPayload := []byte("PING\r\n")
	if _, err := client.Write(shortPayload); err != nil {
		t.Fatalf("write short payload: %v", err)
	}

	res, err := det.Detect(server, 16379)
	if err != nil {
		t.Fatalf("Detect error: %v", err)
	}
	if res.Protocol != ProtoUnknown {
		t.Fatalf("got protocol %q, want %q", res.Protocol, ProtoUnknown)
	}
	if !bytes.Equal(res.Buffered, shortPayload) {
		t.Fatalf("lost short peeked bytes: got %q, want %q", res.Buffered, shortPayload)
	}
}

func TestDetectorConcurrencyRace(t *testing.T) {
	det := NewDefault()
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if id%2 == 0 {
					det.SetDirectPorts([]uint16{3306, 6379, uint16(10000 + j)})
				} else {
					_ = det.IsDirectPort(3306)
					_ = det.DirectPorts()
					_ = det.PeekTimeout()
				}
			}
		}(i)
	}
	wg.Wait()
}
