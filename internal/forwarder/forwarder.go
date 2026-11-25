package forwarder

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultBurpAddr 是本地 Burp Suite 代理默认监听地址。
	DefaultBurpAddr = "127.0.0.1:8080"
	// DefaultDialTimeout 是连接目标或 Burp 的默认拨号超时。
	DefaultDialTimeout = 10 * time.Second
	// DefaultHandshakeTimeout 是与 Burp 建立 HTTP CONNECT 隧道的默认握手超时。
	DefaultHandshakeTimeout       = 10 * time.Second
	maxConnectResponseHeaderBytes = 64 << 10
)

// DialFunc 定义建立底层网络连接的函数签名，便于测试注入自定义拨号逻辑。
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Config 定义转发器的配置项。
type Config struct {
	BurpAddr         string
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	DialContext      DialFunc
}

// Forwarder 提供 Direct 直连和 Burp HTTP CONNECT 隧道两种双向透传通道。
type Forwarder struct {
	mu               sync.RWMutex
	burpAddr         string
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	dialContext      DialFunc
}

// New 根据配置创建并发安全的 Forwarder。
func New(cfg Config) *Forwarder {
	burpAddr := cfg.BurpAddr
	if burpAddr == "" {
		burpAddr = DefaultBurpAddr
	}
	dialTimeout := cfg.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = DefaultDialTimeout
	}
	handshakeTimeout := cfg.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = DefaultHandshakeTimeout
	}
	dialFn := cfg.DialContext
	if dialFn == nil {
		dialer := &net.Dialer{Timeout: dialTimeout}
		dialFn = dialer.DialContext
	}

	return &Forwarder{
		burpAddr:         burpAddr,
		dialTimeout:      dialTimeout,
		handshakeTimeout: handshakeTimeout,
		dialContext:      dialFn,
	}
}

// NewDefault 使用默认配置创建 Forwarder。
func NewDefault() *Forwarder {
	return New(Config{})
}

// BurpAddr 获取当前配置的 Burp 代理地址（并发安全）。
func (f *Forwarder) BurpAddr() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.burpAddr
}

// SetBurpAddr 动态修改 Burp 代理地址（并发安全）。
func (f *Forwarder) SetBurpAddr(addr string) {
	f.mu.Lock()
	f.burpAddr = addr
	f.mu.Unlock()
}

// Direct 直接与目标 host:port 建立 TCP 连接，先写入 Peek 缓冲字节后双向透传。
func (f *Forwarder) Direct(ctx context.Context, clientConn net.Conn, targetAddr string, peeked []byte) error {
	targetConn, err := f.DialDirect(ctx, targetAddr)
	if err != nil {
		_ = clientConn.Close()
		return err
	}
	defer targetConn.Close()

	return Relay(ctx, clientConn, targetConn, peeked, nil)
}

// DialDirect 建立直连，供需要先确认上游连接再应答的调用方使用。
func (f *Forwarder) DialDirect(ctx context.Context, targetAddr string) (net.Conn, error) {
	conn, err := f.dialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("direct dial %s: %w", targetAddr, err)
	}
	return conn, nil
}

// Burp 向当前配置的 Burp 代理建立 CONNECT 隧道并双向透传。
func (f *Forwarder) Burp(ctx context.Context, clientConn net.Conn, targetAddr string, peeked []byte) error {
	return f.BurpAt(ctx, clientConn, f.BurpAddr(), targetAddr, peeked)
}

// BurpAt 向本次路由所选的 Burp 地址建立 CONNECT 隧道。
func (f *Forwarder) BurpAt(ctx context.Context, clientConn net.Conn, burpAddr, targetAddr string, peeked []byte) error {
	if err := ValidateTargetAddr(targetAddr); err != nil {
		_ = clientConn.Close()
		return err
	}
	burpConn, err := f.dialContext(ctx, "tcp", burpAddr)
	if err != nil {
		_ = clientConn.Close()
		return fmt.Errorf("dial burp %s: %w", burpAddr, err)
	}
	defer burpConn.Close()
	stopClosing := context.AfterFunc(ctx, func() { _ = burpConn.Close() })
	defer stopClosing()

	if err := burpConn.SetDeadline(time.Now().Add(f.handshakeTimeout)); err != nil {
		_ = clientConn.Close()
		return fmt.Errorf("set burp handshake deadline: %w", err)
	}

	connectReqRaw := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	if _, err := writeAll(burpConn, []byte(connectReqRaw)); err != nil {
		_ = clientConn.Close()
		return fmt.Errorf("send CONNECT %s to burp %s: %w", targetAddr, burpAddr, err)
	}

	br := bufio.NewReader(io.LimitReader(burpConn, maxConnectResponseHeaderBytes))
	if err := readConnectResponse(br); err != nil {
		_ = clientConn.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("CONNECT %s via burp %s: %w", targetAddr, burpAddr, err)
	}

	if err := burpConn.SetDeadline(time.Time{}); err != nil {
		_ = clientConn.Close()
		return fmt.Errorf("clear burp handshake deadline: %w", err)
	}

	var burpBuffered []byte
	if n := br.Buffered(); n > 0 {
		burpBuffered = make([]byte, n)
		if _, err := io.ReadFull(br, burpBuffered); err != nil {
			_ = clientConn.Close()
			return fmt.Errorf("drain burp buffered tunnel bytes: %w", err)
		}
	}

	return Relay(ctx, clientConn, burpConn, peeked, burpBuffered)
}

// ValidateTargetAddr 检查可作为 CONNECT authority 和 TCP 目标的地址。
func ValidateTargetAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || addr != net.JoinHostPort(host, port) {
		return errors.New("invalid target address")
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return errors.New("invalid target port")
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Zone() == "" {
		return nil
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) > 253 {
		return errors.New("invalid target host")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("invalid target host")
		}
		for i := range len(label) {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return errors.New("invalid target host")
			}
		}
	}
	return nil
}

func readConnectResponse(br *bufio.Reader) error {
	reader := textproto.NewReader(br)
	for {
		line, err := reader.ReadLine()
		if err != nil {
			return fmt.Errorf("read CONNECT status: %w", err)
		}
		proto, status, _ := strings.Cut(line, " ")
		if major, _, ok := http.ParseHTTPVersion(proto); !ok || major != 1 {
			return errors.New("invalid CONNECT response version")
		}
		code, _, _ := strings.Cut(status, " ")
		n, err := strconv.Atoi(code)
		if len(code) != 3 || err != nil || n < 100 || n > 599 {
			return errors.New("invalid CONNECT response status")
		}
		// A successful CONNECT switches to tunnel bytes immediately after the
		// header section, regardless of any HTTP body framing fields.
		if _, err := reader.ReadMIMEHeader(); err != nil {
			return fmt.Errorf("read CONNECT headers: %w", err)
		}
		switch {
		case n >= 200 && n < 300:
			return nil
		case n >= 200 || n == http.StatusSwitchingProtocols:
			return fmt.Errorf("CONNECT rejected with status %d", n)
		}
	}
}

type closeWriter interface {
	CloseWrite() error
}

func closeWriteOrConn(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// Relay 先转发双方已缓冲的字节，再双向拷贝并关闭连接。
func Relay(ctx context.Context, clientConn, upstreamConn net.Conn, clientPeeked, upstreamPeeked []byte) error {
	done := make(chan struct{})
	defer close(done)

	go func() {
		select {
		case <-ctx.Done():
			_ = clientConn.SetDeadline(time.Now())
			_ = upstreamConn.SetDeadline(time.Now())
			_ = clientConn.Close()
			_ = upstreamConn.Close()
		case <-done:
		}
	}()

	errCh := make(chan error, 2)

	// client -> upstream
	go func() {
		if len(clientPeeked) > 0 {
			if _, err := writeAll(upstreamConn, clientPeeked); err != nil {
				_ = upstreamConn.Close()
				_ = clientConn.Close()
				errCh <- fmt.Errorf("write peeked data to upstream: %w", err)
				return
			}
		}
		_, err := io.Copy(upstreamConn, clientConn)
		if err != nil {
			_ = upstreamConn.Close()
			_ = clientConn.Close()
		} else {
			closeWriteOrConn(upstreamConn)
		}
		errCh <- err
	}()

	// upstream -> client
	go func() {
		if len(upstreamPeeked) > 0 {
			if _, err := writeAll(clientConn, upstreamPeeked); err != nil {
				_ = clientConn.Close()
				_ = upstreamConn.Close()
				errCh <- fmt.Errorf("write buffered data to client: %w", err)
				return
			}
		}
		_, err := io.Copy(clientConn, upstreamConn)
		if err != nil {
			_ = clientConn.Close()
			_ = upstreamConn.Close()
		} else {
			closeWriteOrConn(clientConn)
		}
		errCh <- err
	}()

	err1 := <-errCh
	err2 := <-errCh
	_ = upstreamConn.Close()
	_ = clientConn.Close()

	if err := firstRelayError(err1, err2); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	return nil
}

func firstRelayError(errs ...error) error {
	for _, err := range errs {
		if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
			return err
		}
	}
	return nil
}

func writeAll(w io.Writer, data []byte) (int, error) {
	total := 0
	for total < len(data) {
		n, err := w.Write(data[total:])
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
