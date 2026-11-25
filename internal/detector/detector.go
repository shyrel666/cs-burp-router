package detector

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"sync"
	"time"
)

// Protocol 表示连接识别出的应用层协议类型。
type Protocol string

const (
	ProtoHTTP    Protocol = "HTTP"
	ProtoTLS     Protocol = "TLS/HTTPS"
	ProtoUnknown Protocol = "TCP/Unknown"
)

const (
	// DefaultPeekTimeout 是非白名单端口窥探首包的默认读取超时。
	DefaultPeekTimeout = 200 * time.Millisecond
	// PeekSize 是协议识别窥探的前缀字节数。
	PeekSize = 8
)

var defaultDirectPorts = []uint16{
	1433,  // MSSQL
	3306,  // MySQL
	1521,  // Oracle
	5432,  // PostgreSQL
	6379,  // Redis
	27017, // MongoDB
	21,    // FTP
	22,    // SSH
	25,    // SMTP
}

var httpMethodPrefixes = [8]string{
	"GET ",
	"POST",
	"PUT ",
	"DELE",
	"HEAD",
	"OPTI",
	"PATC",
	"CONN",
}

// DefaultDirectPorts 返回默认跳过 Peek 直连放行的端口白名单副本。
func DefaultDirectPorts() []uint16 {
	out := make([]uint16, len(defaultDirectPorts))
	copy(out, defaultDirectPorts)
	return out
}

// Config 定义协议探测器的配置项。
type Config struct {
	// DirectPorts 为跳过 Peek 的直连端口列表。为 nil 时使用 DefaultDirectPorts()；传空切片表示禁用端口白名单。
	DirectPorts []uint16
	// PeekTimeout 为读取客户端首包超时时间，<= 0 时使用 DefaultPeekTimeout (200ms)。
	PeekTimeout time.Duration
}

// Result 保存协议探测结果及 Peek 阶段已缓冲的全部原始字节。
type Result struct {
	Protocol Protocol
	// Buffered 保存 Peek 过程中从底层连接读入缓冲区的全部字节，后续转发必须先原样写出以避免丢字节。
	Buffered []byte
	// FastPath 为 true 表示命中直连端口白名单并跳过了 Peek。
	FastPath bool
}

// Detector 负责对入站连接执行端口快车道判断与短超时首包协议窥探。
type Detector struct {
	mu          sync.RWMutex
	directPorts map[uint16]struct{}
	peekTimeout time.Duration
}

// New 根据给定配置创建并发安全的 Detector。
func New(cfg Config) *Detector {
	ports := cfg.DirectPorts
	if ports == nil {
		ports = defaultDirectPorts
	}
	timeout := cfg.PeekTimeout
	if timeout <= 0 {
		timeout = DefaultPeekTimeout
	}

	d := &Detector{
		peekTimeout: timeout,
	}
	d.SetDirectPorts(ports)
	return d
}

// NewDefault 使用规范默认配置创建 Detector。
func NewDefault() *Detector {
	return New(Config{})
}

// IsDirectPort 判断目标端口是否命中直连白名单。
func (d *Detector) IsDirectPort(port uint16) bool {
	d.mu.RLock()
	_, ok := d.directPorts[port]
	d.mu.RUnlock()
	return ok
}

// SetDirectPorts 动态更新直连端口白名单（并发安全）。
func (d *Detector) SetDirectPorts(ports []uint16) {
	m := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		m[p] = struct{}{}
	}
	d.mu.Lock()
	d.directPorts = m
	d.mu.Unlock()
}

// DirectPorts 返回当前生效的直连白名单端口列表（升序排列）。
func (d *Detector) DirectPorts() []uint16 {
	d.mu.RLock()
	out := make([]uint16, 0, len(d.directPorts))
	for p := range d.directPorts {
		out = append(out, p)
	}
	d.mu.RUnlock()
	slices.Sort(out)
	return out
}

// PeekTimeout 返回当前配置的窥探读取超时。
func (d *Detector) PeekTimeout() time.Duration {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.peekTimeout
}

// Detect 按规范优先级判定协议：
// 1. 命中端口白名单直接跳过 Peek，返回 TCP/Unknown (FastPath=true)；
// 2. 其他端口设置 200ms 读取超时，使用 bufio.Reader.Peek(8) 窥探首包并完整提取缓冲区内所有已读字节。
func (d *Detector) Detect(conn net.Conn, targetPort uint16) (Result, error) {
	if d.IsDirectPort(targetPort) {
		return Result{
			Protocol: ProtoUnknown,
			FastPath: true,
		}, nil
	}
	return d.Peek(conn)
}

// Peek 读取用于判别协议的前缀，供已完成端口规则判断的调用方使用。
func (d *Detector) Peek(conn net.Conn) (Result, error) {
	timeout := d.PeekTimeout()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return Result{}, fmt.Errorf("set peek read deadline: %w", err)
	}
	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()

	br := bufio.NewReader(conn)
	_, peekErr := br.Peek(PeekSize)

	var buffered []byte
	if n := br.Buffered(); n > 0 {
		buffered = make([]byte, n)
		if _, err := io.ReadFull(br, buffered); err != nil {
			return Result{}, fmt.Errorf("drain peek buffer: %w", err)
		}
	}

	if peekErr != nil && !isTimeoutError(peekErr) && !errors.Is(peekErr, io.EOF) && len(buffered) == 0 {
		return Result{}, peekErr
	}

	return Result{
		Protocol: Classify(buffered),
		Buffered: buffered,
		FastPath: false,
	}, nil
}

// Classify 根据窥探到的前导字节判定协议类型。
func Classify(data []byte) Protocol {
	if len(data) >= 2 && data[0] == 0x16 && data[1] == 0x03 {
		return ProtoTLS
	}
	if len(data) >= 4 {
		prefix := string(data[:4])
		for _, m := range httpMethodPrefixes {
			if prefix == m {
				return ProtoHTTP
			}
		}
	}
	return ProtoUnknown
}

func isTimeoutError(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
