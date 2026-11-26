package detector

import (
	"bufio"
	"encoding/binary"
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
	// TLSReadTimeout 为识别到 TLS 记录头后继续读取完整 ClientHello 的额外超时，<= 0 时使用 DefaultTLSReadTimeout (100ms)。
	TLSReadTimeout time.Duration
}

// Result 保存协议探测结果及 Peek 阶段已缓冲的全部原始字节。
type Result struct {
	Protocol Protocol
	// Buffered 保存 Peek 过程中从底层连接读入缓冲区的全部字节，后续转发必须先原样写出以避免丢字节。
	Buffered []byte
	// FastPath 为 true 表示命中直连端口白名单并跳过了 Peek。
	FastPath bool
	// SNI 为从 TLS ClientHello server_name 扩展解析出的主机名（非 TLS 或未携带时为空）。
	SNI string
	// TLSVersion 为客户端声明支持的最高 TLS 版本（如 "TLS 1.3" / "TLS 1.2" / "TLS 1.1" / "TLS 1.0"）。
	TLSVersion string
	// WeakTLS 当客户端最高仅支持 TLS 1.0 或 TLS 1.1（或更低版本）时为 true。
	WeakTLS bool
}

// Detector 负责对入站连接执行端口快车道判断与短超时首包协议窥探。
type Detector struct {
	mu             sync.RWMutex
	directPorts    map[uint16]struct{}
	peekTimeout    time.Duration
	tlsReadTimeout time.Duration
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
	tlsTimeout := cfg.TLSReadTimeout
	if tlsTimeout <= 0 {
		tlsTimeout = DefaultTLSReadTimeout
	}

	d := &Detector{
		peekTimeout:    timeout,
		tlsReadTimeout: tlsTimeout,
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

// TLSReadTimeout 返回读取完整 TLS ClientHello 记录的额外读取超时。
func (d *Detector) TLSReadTimeout() time.Duration {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.tlsReadTimeout
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

	proto := Classify(buffered)
	res := Result{
		Protocol: proto,
		Buffered: buffered,
		FastPath: false,
	}

	// 仅当前两字节命中 TLS 记录头 (0x16 0x03) 时，尝试补读完整 TLS Record（上限 4096 字节，额外超时 100ms）以解析 SNI 与版本。
	// 无论读取超时、截断还是解析异常，均不报错中断连接，且所有已读字节完整保留在 res.Buffered 中。
	if proto == ProtoTLS && len(buffered) >= 5 {
		recordLen := int(binary.BigEndian.Uint16(buffered[3:5]))
		wantTotal := 5 + recordLen
		if wantTotal > MaxTLSRecordInspectSize {
			wantTotal = MaxTLSRecordInspectSize
		}
		if len(buffered) < wantTotal && peekErr == nil {
			if err := conn.SetReadDeadline(time.Now().Add(d.TLSReadTimeout())); err == nil {
				extra := make([]byte, wantTotal-len(buffered))
				n, _ := io.ReadFull(conn, extra)
				if n > 0 {
					buffered = append(buffered, extra[:n]...)
					res.Buffered = buffered
				}
			}
		}
		info := ParseClientHello(res.Buffered)
		res.SNI = info.SNI
		res.TLSVersion = info.TLSVersion
		res.WeakTLS = info.WeakTLS
	}

	return res, nil
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
