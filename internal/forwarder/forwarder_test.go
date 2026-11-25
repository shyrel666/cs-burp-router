package forwarder

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestForwardDirectWithPeekedBytes(t *testing.T) {
	// 启动模拟目标 TCP 服务端：读取完整请求并回写响应
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()

	wantFullClientStream := []byte("CUSTOM_HEADER_12345678|remaining-body-payload")
	wantServerReply := []byte("SERVER_ACK_OK")

	targetErrCh := make(chan error, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			targetErrCh <- err
			return
		}
		defer conn.Close()

		got, err := io.ReadAll(conn)
		if err != nil {
			targetErrCh <- err
			return
		}
		if !bytes.Equal(got, wantFullClientStream) {
			targetErrCh <- fmt.Errorf("target got %q, want %q", got, wantFullClientStream)
			return
		}
		_, err = conn.Write(wantServerReply)
		targetErrCh <- err
	}()

	// 准备客户端与路由端连接对
	routerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen router: %v", err)
	}
	defer routerLn.Close()

	fwdDone := make(chan error, 1)
	fwd := NewDefault()
	go func() {
		srvSide, err := routerLn.Accept()
		if err != nil {
			fwdDone <- err
			return
		}
		// 模拟 Peek 已缓冲前 14 字节
		peeked := wantFullClientStream[:14]
		fwdDone <- fwd.Direct(context.Background(), srvSide, targetLn.Addr().String(), peeked)
	}()

	clientConn, err := net.Dial("tcp", routerLn.Addr().String())
	if err != nil {
		t.Fatalf("dial router: %v", err)
	}
	defer clientConn.Close()

	// 客户端仅发送剩余未缓冲字节并半关闭写端
	if _, err := clientConn.Write(wantFullClientStream[14:]); err != nil {
		t.Fatalf("client write remaining: %v", err)
	}
	_ = clientConn.(*net.TCPConn).CloseWrite()

	gotReply, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("client read reply: %v", err)
	}
	if !bytes.Equal(gotReply, wantServerReply) {
		t.Fatalf("client got reply %q, want %q", gotReply, wantServerReply)
	}

	if err := <-targetErrCh; err != nil {
		t.Fatalf("target server error: %v", err)
	}
	if err := <-fwdDone; err != nil {
		t.Fatalf("Direct forwarder error: %v", err)
	}
}

func TestForwardBurpConnectTunnel(t *testing.T) {
	const wantTarget = "api.example.local:8443"
	wantPayload := []byte("GET /secret HTTP/1.1\r\nHost: api.example.local:8443\r\n\r\n")
	wantResponse := []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nproxied")

	// 启动模拟 Burp 代理服务端
	burpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock burp: %v", err)
	}
	defer burpLn.Close()

	burpErrCh := make(chan error, 1)
	go func() {
		conn, err := burpLn.Accept()
		if err != nil {
			burpErrCh <- err
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		req, err := http.ReadRequest(br)
		if err != nil {
			burpErrCh <- fmt.Errorf("burp read CONNECT request: %w", err)
			return
		}
		if req.Method != http.MethodConnect {
			burpErrCh <- fmt.Errorf("got method %q, want CONNECT", req.Method)
			return
		}
		if req.Host != wantTarget {
			burpErrCh <- fmt.Errorf("got CONNECT host %q, want %q", req.Host, wantTarget)
			return
		}

		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			burpErrCh <- err
			return
		}

		tunneled := make([]byte, len(wantPayload))
		if _, err := io.ReadFull(br, tunneled); err != nil {
			burpErrCh <- fmt.Errorf("burp read tunneled payload: %w", err)
			return
		}
		if !bytes.Equal(tunneled, wantPayload) {
			burpErrCh <- fmt.Errorf("tunneled payload mismatch: got %q, want %q", tunneled, wantPayload)
			return
		}

		_, err = conn.Write(wantResponse)
		burpErrCh <- err
	}()

	routerLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen router: %v", err)
	}
	defer routerLn.Close()

	fwd := New(Config{BurpAddr: burpLn.Addr().String()})
	fwdDone := make(chan error, 1)
	go func() {
		srvSide, err := routerLn.Accept()
		if err != nil {
			fwdDone <- err
			return
		}
		fwdDone <- fwd.Burp(context.Background(), srvSide, wantTarget, wantPayload[:8])
	}()

	clientConn, err := net.Dial("tcp", routerLn.Addr().String())
	if err != nil {
		t.Fatalf("dial router: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.Write(wantPayload[8:]); err != nil {
		t.Fatalf("client write rest: %v", err)
	}

	gotResp, err := io.ReadAll(clientConn)
	if err != nil {
		t.Fatalf("client read response: %v", err)
	}
	_ = clientConn.Close()

	if !bytes.Equal(gotResp, wantResponse) {
		t.Fatalf("client got %q, want %q", gotResp, wantResponse)
	}
	if err := <-burpErrCh; err != nil {
		t.Fatalf("mock burp error: %v", err)
	}
	if err := <-fwdDone; err != nil {
		t.Fatalf("Burp forwarder error: %v", err)
	}
}

func TestForwardBurpNon200Rejected(t *testing.T) {
	burpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen mock burp: %v", err)
	}
	defer burpLn.Close()

	go func() {
		conn, err := burpLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		_, _ = http.ReadRequest(br)
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
	}()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	fwd := New(Config{
		BurpAddr:         burpLn.Addr().String(),
		HandshakeTimeout: 2 * time.Second,
	})
	err = fwd.Burp(context.Background(), c2, "example.com:443", []byte{0x16, 0x03, 0x01})
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("expected 502 rejection error, got: %v", err)
	}
}

func TestReadConnectResponsePreservesTunnelBytes(t *testing.T) {
	response := "HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 202 Accepted\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"first tunnel bytes"
	br := bufio.NewReader(strings.NewReader(response))
	if err := readConnectResponse(br); err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	data, err := io.ReadAll(br)
	if err != nil || string(data) != "first tunnel bytes" {
		t.Fatalf("tunnel bytes = %q, err = %v", data, err)
	}
}

func TestValidateTargetAddr(t *testing.T) {
	for _, addr := range []string{"api.example.test.:8443", "[2001:db8::1]:443", "192.0.2.1:80"} {
		if err := ValidateTargetAddr(addr); err != nil {
			t.Errorf("rejected %q: %v", addr, err)
		}
	}
	for _, addr := range []string{"bad host.test:80", "missing-port.test", "[host.test]:80", "host.test:0"} {
		if err := ValidateTargetAddr(addr); err == nil {
			t.Errorf("accepted invalid target %q", addr)
		}
	}
}
