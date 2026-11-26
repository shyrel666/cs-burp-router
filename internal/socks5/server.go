package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"cs-burp-router/internal/detector"
	"cs-burp-router/internal/forwarder"
)

const (
	// DefaultListenAddr 是本地 SOCKS5 服务端默认监听地址。
	DefaultListenAddr = "127.0.0.1:10808"
	// DefaultHandshakeTimeout 是 SOCKS5 握手阶段的默认超时时间。
	DefaultHandshakeTimeout = 10 * time.Second

	socksVersion5 = 0x05

	authNone         = 0x00
	authNoAcceptable = 0xFF

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess              = 0x00
	repGeneralFailure       = 0x01
	repNotAllowed           = 0x02
	repNetworkUnreachable   = 0x03
	repHostUnreachable      = 0x04
	repConnectionRefused    = 0x05
	repCmdNotSupported      = 0x07
	repAddrTypeNotSupported = 0x08
)

// RouteAction 表示连接最终执行的路由转发动作。
type RouteAction string

const (
	ActionBurp     RouteAction = "Burp"
	ActionDirect   RouteAction = "Direct"
	ActionRejected RouteAction = "Rejected"
)

// DecisionEvent 记录单条连接完成协议识别后的路由决策信息。
type DecisionEvent struct {
	Time       time.Time
	ClientAddr string
	TargetHost string
	TargetPort uint16
	TargetAddr string
	Protocol   detector.Protocol
	Action     RouteAction
	Reason     string
	Pinned     bool
	SNI        string
	TLSVersion string
	WeakTLS    bool
}

// ConnStartEvent 描述连接进入活跃转发（或被规则拒绝）时的初始元数据，用于连接追踪器记录。
type ConnStartEvent struct {
	Time       time.Time
	ClientAddr string
	TargetHost string
	TargetPort uint16
	TargetAddr string
	// Protocol 取值：HTTP / TLS/HTTPS / TCP/Unknown / FastPath / Loopback / Pinned
	Protocol string
	// Action 取值：Burp / Direct / Rejected
	Action     RouteAction
	Reason     string
	Pinned     bool
	SNI        string
	TLSVersion string
	WeakTLS    bool
}

// LifecycleHooks 定义连接生命周期回调钩子（必须并发安全）。
type LifecycleHooks struct {
	// OnConnStart 在完成路由决策进入 Active 状态时触发，返回追踪记录 ID。
	OnConnStart func(ev ConnStartEvent) uint64
	// OnConnEnd 在连接关闭或出错结束时触发；err == nil 表示 Closed，err != nil 表示 Error。
	OnConnEnd func(id uint64, err error)
}

// Config 定义本地 SOCKS5 服务端的配置项。
type Config struct {
	ListenAddr       string
	Detector         *detector.Detector
	Forwarder        *forwarder.Forwarder
	HandshakeTimeout time.Duration
	// BypassAll 开启后，除自身监听回环拒绝流量外，所有新连接跳过 Peek 直接走 Direct 直连。
	BypassAll bool
	// BypassAddrs 为额外强制排除（不经过 Burp 代理、直接直连）的本地监听地址列表，例如 Web 面板 127.0.0.1:18080。
	BypassAddrs []string
	// OnDecision 在每条连接得出路由决策时回调（必须并发安全）。
	OnDecision func(DecisionEvent)
	// Hooks 提供连接建立（Active）与结束（Closed / Error）生命周期事件钩子。
	Hooks LifecycleHooks
	// Logger 为可选日志输出器；为 nil 时不主动打印底层错误。
	Logger *log.Logger
}

// RoutingConfig 是当前生效的路由设置快照。
type RoutingConfig struct {
	BurpAddr    string
	DirectPorts []uint16
	BypassAll   bool
}

// RoutingUpdate 指定一次配置提交中要更新的字段。
type RoutingUpdate struct {
	BurpAddr    *string
	DirectPorts *[]uint16
	BypassAll   *bool
}

// Server 是串联协议窥探与双通道转发的本地无认证 SOCKS5 服务端。
type Server struct {
	listenAddr       string
	detector         *detector.Detector
	forwarder        *forwarder.Forwarder
	handshakeTimeout time.Duration
	bypassAddrs      []string
	onDecision       func(DecisionEvent)
	hooks            LifecycleHooks
	logger           *log.Logger

	routingMu sync.RWMutex
	bypassAll bool
	overrides map[string]RouteAction

	ctx    context.Context
	cancel context.CancelFunc

	mu         sync.RWMutex
	ln         net.Listener
	actualAddr string
	closed     bool
	conns      map[net.Conn]struct{}

	wg sync.WaitGroup
}

// NewServer 根据给定配置创建 SOCKS5 Server。
func NewServer(cfg Config) *Server {
	listenAddr := cfg.ListenAddr
	if listenAddr == "" {
		listenAddr = DefaultListenAddr
	}
	det := cfg.Detector
	if det == nil {
		det = detector.NewDefault()
	}
	fwd := cfg.Forwarder
	if fwd == nil {
		fwd = forwarder.NewDefault()
	}
	hsTimeout := cfg.HandshakeTimeout
	if hsTimeout <= 0 {
		hsTimeout = DefaultHandshakeTimeout
	}
	bypass := make([]string, len(cfg.BypassAddrs))
	copy(bypass, cfg.BypassAddrs)

	ctx, cancel := context.WithCancel(context.Background())
	srv := &Server{
		listenAddr:       listenAddr,
		detector:         det,
		forwarder:        fwd,
		handshakeTimeout: hsTimeout,
		bypassAddrs:      bypass,
		onDecision:       cfg.OnDecision,
		hooks:            cfg.Hooks,
		logger:           cfg.Logger,
		bypassAll:        cfg.BypassAll,
		overrides:        make(map[string]RouteAction),
		ctx:              ctx,
		cancel:           cancel,
		conns:            make(map[net.Conn]struct{}),
	}
	return srv
}

// Addr 返回服务端实际绑定的监听地址（若尚未启动则返回配置的 ListenAddr）。
func (s *Server) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.actualAddr != "" {
		return s.actualAddr
	}
	return s.listenAddr
}

// BypassAll 返回当前全局直连开关状态（并发安全）。
func (s *Server) BypassAll() bool {
	s.routingMu.RLock()
	defer s.routingMu.RUnlock()
	return s.bypassAll
}

// SetBypassAll 动态更新全局直连开关状态，对后续新连接立即生效（并发安全）。
func (s *Server) SetBypassAll(v bool) {
	s.routingMu.Lock()
	s.bypassAll = v
	s.routingMu.Unlock()
}

// RoutingConfig 获取一份一致的路由配置快照。
func (s *Server) RoutingConfig() RoutingConfig {
	s.routingMu.RLock()
	defer s.routingMu.RUnlock()
	return s.routingConfigLocked()
}

// UpdateRoutingConfig 同时更新本次提交的所有字段，并返回更新后的快照。
func (s *Server) UpdateRoutingConfig(update RoutingUpdate) RoutingConfig {
	s.routingMu.Lock()
	defer s.routingMu.Unlock()
	if update.BurpAddr != nil {
		s.forwarder.SetBurpAddr(*update.BurpAddr)
	}
	if update.DirectPorts != nil {
		s.detector.SetDirectPorts(*update.DirectPorts)
	}
	if update.BypassAll != nil {
		s.bypassAll = *update.BypassAll
	}
	return s.routingConfigLocked()
}

func (s *Server) routingConfigLocked() RoutingConfig {
	return RoutingConfig{
		BurpAddr:    s.forwarder.BurpAddr(),
		DirectPorts: s.detector.DirectPorts(),
		BypassAll:   s.bypassAll,
	}
}

func (s *Server) routeForPort(port uint16) (burpAddr string, bypassAll, directPort bool) {
	s.routingMu.RLock()
	defer s.routingMu.RUnlock()
	return s.forwarder.BurpAddr(), s.bypassAll, s.detector.IsDirectPort(port)
}

func (s *Server) routeForTarget(host string, port uint16) (burpAddr string, bypassAll bool, overrideAction RouteAction, overridePinned bool, directPort bool) {
	s.routingMu.RLock()
	defer s.routingMu.RUnlock()
	overrideAction, overridePinned = matchOverrideMap(s.overrides, host, port)
	return s.forwarder.BurpAddr(), s.bypassAll, overrideAction, overridePinned, s.detector.IsDirectPort(port)
}

// SetOverride 添加或更新单条目标路由覆盖规则（支持 host:port 或 host，并发安全）。
func (s *Server) SetOverride(target string, action RouteAction) (OverrideRule, error) {
	normTarget, err := NormalizeOverrideTarget(target)
	if err != nil {
		return OverrideRule{}, err
	}
	if err := ValidateOverrideAction(action); err != nil {
		return OverrideRule{}, err
	}
	s.routingMu.Lock()
	s.overrides[normTarget] = action
	s.routingMu.Unlock()
	return OverrideRule{Target: normTarget, Action: action}, nil
}

// DeleteOverride 移除指定目标的覆盖规则，返回规则此前是否存在（并发安全）。
func (s *Server) DeleteOverride(target string) (bool, error) {
	normTarget, err := NormalizeOverrideTarget(target)
	if err != nil {
		return false, err
	}
	s.routingMu.Lock()
	_, existed := s.overrides[normTarget]
	delete(s.overrides, normTarget)
	s.routingMu.Unlock()
	return existed, nil
}

// ClearOverrides 清空当前全部目标覆盖规则（并发安全）。
func (s *Server) ClearOverrides() {
	s.routingMu.Lock()
	clear(s.overrides)
	s.routingMu.Unlock()
}

// Overrides 返回按目标升序排列的全部覆盖规则快照（并发安全）。
func (s *Server) Overrides() []OverrideRule {
	s.routingMu.RLock()
	defer s.routingMu.RUnlock()
	return listOverrideMap(s.overrides)
}

// MatchOverride 检查目标是否命中覆盖规则（精确 host:port 优先于 host，并发安全）。
func (s *Server) MatchOverride(targetHost string, targetPort uint16) (RouteAction, bool) {
	s.routingMu.RLock()
	defer s.routingMu.RUnlock()
	return matchOverrideMap(s.overrides, targetHost, targetPort)
}

// Detector 返回当前关联的协议探测器实例。
func (s *Server) Detector() *detector.Detector {
	return s.detector
}

// Forwarder 返回当前关联的转发器实例。
func (s *Server) Forwarder() *forwarder.Forwarder {
	return s.forwarder
}

// ListenAndServe 在配置的 ListenAddr 上启动 TCP 监听并持续处理连接。
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("socks5 listen %s: %w", s.listenAddr, err)
	}
	return s.Serve(ln)
}

// Serve 使用给定的 net.Listener 接收并处理 SOCKS5 连接，直到 Server 被关闭或发生不可恢复错误。
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = ln.Close()
		return net.ErrClosed
	}
	s.ln = ln
	s.actualAddr = ln.Addr().String()
	s.mu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.isClosed() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("socks5 accept: %w", err)
		}

		if !s.trackConn(conn) {
			_ = conn.Close()
			continue
		}

		go func(c net.Conn) {
			defer s.wg.Done()
			defer s.untrackConn(c)
			defer c.Close()
			s.handleConn(c)
		}(conn)
	}
}

// Close 停止接收新连接、中断所有活跃连接并等待后台协程安全退出。
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.wg.Wait()
		return nil
	}
	s.closed = true
	ln := s.ln
	activeConns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		activeConns = append(activeConns, c)
	}
	s.mu.Unlock()

	s.cancel()

	var closeErr error
	if ln != nil {
		closeErr = ln.Close()
	}
	for _, c := range activeConns {
		_ = c.SetDeadline(time.Now())
		_ = c.Close()
	}

	s.wg.Wait()
	return closeErr
}

func (s *Server) isClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

func (s *Server) trackConn(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}
	s.wg.Add(1)
	return true
}

func (s *Server) untrackConn(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) handleConn(clientConn net.Conn) {
	if err := clientConn.SetDeadline(time.Now().Add(s.handshakeTimeout)); err != nil {
		s.logf("set socks5 handshake deadline error: %v", err)
		return
	}

	if err := negotiateAuth(clientConn); err != nil {
		if !s.isClosed() {
			s.logf("socks5 auth error from %s: %v", clientConn.RemoteAddr(), err)
		}
		return
	}

	targetHost, targetPort, err := readConnectRequest(clientConn)
	if err != nil {
		// ProxyBridge 后台会周期性发送 UDP ASSOCIATE (0x03) 探测，按协议返回 0x07 后静默关闭，避免刷屏误导用户。
		if !s.isClosed() && !errors.Is(err, errUDPAssociateUnsupported) {
			s.logf("socks5 request error from %s: %v", clientConn.RemoteAddr(), err)
		}
		return
	}

	if err := clientConn.SetDeadline(time.Time{}); err != nil {
		s.logf("clear socks5 handshake deadline error: %v", err)
		return
	}

	clientAddr := ""
	if clientConn.RemoteAddr() != nil {
		clientAddr = clientConn.RemoteAddr().String()
	}
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))
	now := time.Now()

	// 阻止连接回 SOCKS5 服务端自身监听端口，防止自连接死循环。
	if isSameEndpoint(targetHost, targetPort, s.Addr()) {
		_ = writeReply(clientConn, repNotAllowed)
		rejectErr := fmt.Errorf("rejected self-loopback connection to socks5 %s", targetAddr)
		connID := s.emitConnStart(ConnStartEvent{
			Time:       now,
			ClientAddr: clientAddr,
			TargetHost: targetHost,
			TargetPort: targetPort,
			TargetAddr: targetAddr,
			Protocol:   "Loopback",
			Action:     ActionRejected,
			Reason:     "self-loopback",
		})
		s.emitConnEnd(connID, rejectErr)
		s.logf("rejected self-loopback connection from %s to socks5 %s", clientAddr, targetAddr)
		return
	}

	burpAddr, bypassAll, overrideAction, overridePinned, directPort := s.routeForTarget(targetHost, targetPort)
	action := ActionDirect
	protocol := detector.ProtoUnknown
	decisionTime := now
	var (
		reason     string
		trackProto string
		pinned     bool
		sni        string
		tlsVersion string
		weakTLS    bool
		buffered   []byte
		replied    bool
	)
	// 严格路由优先级：自回环/自身排除 > BypassAll 全局直连 > 目标覆盖规则（Pin） > DirectPorts 端口白名单 > 200ms 协议窥探
	switch {
	case s.shouldBypassBurp(targetHost, targetPort, burpAddr):
		reason, trackProto = "loopback-bypass", "Loopback"
	case bypassAll:
		reason, trackProto = "bypass-all", "FastPath"
	case overridePinned:
		pinned = true
		action = overrideAction
		trackProto = "Pinned"
		if overrideAction == ActionBurp {
			reason = "override-burp"
			if err := writeReply(clientConn, repSuccess); err != nil {
				s.logf("write socks5 success reply to %s: %v", clientAddr, err)
				return
			}
			replied = true
		} else {
			reason = "override-direct"
		}
	case directPort:
		reason, trackProto = "port-whitelist", "FastPath"
	default:
		// Protocol detection needs application bytes, which most SOCKS5
		// clients send only after the CONNECT reply.
		if err := writeReply(clientConn, repSuccess); err != nil {
			s.logf("write socks5 success reply to %s: %v", clientAddr, err)
			return
		}
		replied = true
		result, err := s.detector.Peek(clientConn)
		if err != nil {
			if !s.isClosed() {
				connID := s.emitConnStart(ConnStartEvent{
					Time:       time.Now(),
					ClientAddr: clientAddr,
					TargetHost: targetHost,
					TargetPort: targetPort,
					TargetAddr: targetAddr,
					Protocol:   string(detector.ProtoUnknown),
					Action:     ActionDirect,
					Reason:     "detect-error",
				})
				s.emitConnEnd(connID, err)
				s.logf("detect protocol for %s error: %v", targetAddr, err)
			}
			return
		}
		decisionTime = time.Now()
		protocol = result.Protocol
		trackProto = string(protocol)
		sni = result.SNI
		tlsVersion = result.TLSVersion
		weakTLS = result.WeakTLS
		buffered = result.Buffered
		switch protocol {
		case detector.ProtoHTTP:
			action, reason = ActionBurp, "peek-http"
		case detector.ProtoTLS:
			action, reason = ActionBurp, "peek-tls"
		default:
			reason = "peek-unknown"
		}
	}

	s.emitDecision(DecisionEvent{
		Time:       decisionTime,
		ClientAddr: clientAddr,
		TargetHost: targetHost,
		TargetPort: targetPort,
		TargetAddr: targetAddr,
		Protocol:   protocol,
		Action:     action,
		Reason:     reason,
		Pinned:     pinned,
		SNI:        sni,
		TLSVersion: tlsVersion,
		WeakTLS:    weakTLS,
	})
	connID := s.emitConnStart(ConnStartEvent{
		Time:       decisionTime,
		ClientAddr: clientAddr,
		TargetHost: targetHost,
		TargetPort: targetPort,
		TargetAddr: targetAddr,
		Protocol:   trackProto,
		Action:     action,
		Reason:     reason,
		Pinned:     pinned,
		SNI:        sni,
		TLSVersion: tlsVersion,
		WeakTLS:    weakTLS,
	})

	switch {
	case action == ActionBurp:
		err = s.forwarder.BurpAt(s.ctx, clientConn, burpAddr, targetAddr, buffered)
	case replied:
		err = s.forwarder.Direct(s.ctx, clientConn, targetAddr, buffered)
	default:
		err = s.forwardDirect(clientConn, targetAddr)
	}
	s.emitConnEnd(connID, s.normalizeForwardErr(err))
	if err != nil && !s.isClosed() {
		s.logf("forward (%s) %s error: %v", action, targetAddr, err)
	}
}

func (s *Server) forwardDirect(clientConn net.Conn, targetAddr string) error {
	targetConn, err := s.forwarder.DialDirect(s.ctx, targetAddr)
	if err != nil {
		_ = writeReply(clientConn, directFailureReply(err))
		return err
	}
	defer targetConn.Close()
	if err := writeConnectReply(clientConn, targetConn.LocalAddr()); err != nil {
		return fmt.Errorf("write socks5 success reply: %w", err)
	}
	return forwarder.Relay(s.ctx, clientConn, targetConn, nil, nil)
}

func directFailureReply(err error) byte {
	// Winsock uses its own error numbers for connect failures.
	const (
		wsaNetUnreachable  = syscall.Errno(10051)
		wsaConnRefused     = syscall.Errno(10061)
		wsaHostUnreachable = syscall.Errno(10065)
	)
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, syscall.ECONNREFUSED) || runtime.GOOS == "windows" && errors.Is(err, wsaConnRefused):
		return repConnectionRefused
	case errors.Is(err, syscall.ENETUNREACH) || runtime.GOOS == "windows" && errors.Is(err, wsaNetUnreachable):
		return repNetworkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH) ||
		runtime.GOOS == "windows" && errors.Is(err, wsaHostUnreachable) || errors.As(err, &dnsErr):
		return repHostUnreachable
	default:
		return repGeneralFailure
	}
}

func (s *Server) normalizeForwardErr(err error) error {
	if err == nil {
		return nil
	}
	if s.isClosed() && errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (s *Server) shouldBypassBurp(targetHost string, targetPort uint16, burpAddr string) bool {
	if isSameEndpoint(targetHost, targetPort, burpAddr) {
		return true
	}
	for _, addr := range s.bypassAddrs {
		if isSameEndpoint(targetHost, targetPort, addr) {
			return true
		}
	}
	return false
}

func (s *Server) emitDecision(ev DecisionEvent) {
	if s.onDecision != nil {
		s.onDecision(ev)
	}
}

func (s *Server) emitConnStart(ev ConnStartEvent) uint64 {
	if s.hooks.OnConnStart != nil {
		return s.hooks.OnConnStart(ev)
	}
	return 0
}

func (s *Server) emitConnEnd(id uint64, err error) {
	if s.hooks.OnConnEnd != nil {
		s.hooks.OnConnEnd(id, err)
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.logger != nil {
		s.logger.Printf(format, args...)
	}
}

func negotiateAuth(conn net.Conn) error {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return fmt.Errorf("read greeting header: %w", err)
	}
	if hdr[0] != socksVersion5 {
		return fmt.Errorf("unsupported socks version: 0x%02x", hdr[0])
	}
	nMethods := int(hdr[1])
	if nMethods == 0 {
		_, _ = conn.Write([]byte{socksVersion5, authNoAcceptable})
		return errors.New("client offered zero auth methods")
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("read auth methods: %w", err)
	}

	hasNoAuth := false
	for _, m := range methods {
		if m == authNone {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		_, _ = conn.Write([]byte{socksVersion5, authNoAcceptable})
		return errors.New("no acceptable auth method (only NO AUTH 0x00 supported)")
	}

	if _, err := conn.Write([]byte{socksVersion5, authNone}); err != nil {
		return fmt.Errorf("write auth selection: %w", err)
	}
	return nil
}

var errUDPAssociateUnsupported = errors.New("socks5 UDP ASSOCIATE (0x03) is not supported")

func readConnectRequest(conn net.Conn) (string, uint16, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return "", 0, fmt.Errorf("read request header: %w", err)
	}
	if hdr[0] != socksVersion5 {
		return "", 0, fmt.Errorf("invalid request socks version: 0x%02x", hdr[0])
	}

	cmd := hdr[1]
	atyp := hdr[3]

	var host string
	switch atyp {
	case atypIPv4:
		var ipBuf [4]byte
		if _, err := io.ReadFull(conn, ipBuf[:]); err != nil {
			return "", 0, fmt.Errorf("read ipv4 address: %w", err)
		}
		host = net.IP(ipBuf[:]).String()

	case atypDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return "", 0, fmt.Errorf("read domain length: %w", err)
		}
		domainLen := int(lenBuf[0])
		if domainLen == 0 {
			var portDiscard [2]byte
			_, _ = io.ReadFull(conn, portDiscard[:])
			_ = writeReply(conn, repHostUnreachable)
			return "", 0, errors.New("empty domain name in request")
		}
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return "", 0, fmt.Errorf("read domain address: %w", err)
		}
		host = string(domainBuf)

	case atypIPv6:
		var ipBuf [16]byte
		if _, err := io.ReadFull(conn, ipBuf[:]); err != nil {
			return "", 0, fmt.Errorf("read ipv6 address: %w", err)
		}
		host = net.IP(ipBuf[:]).String()

	default:
		_ = writeReply(conn, repAddrTypeNotSupported)
		return "", 0, fmt.Errorf("unsupported address type: 0x%02x", atyp)
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return "", 0, fmt.Errorf("read target port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	if cmd != cmdConnect {
		_ = writeReply(conn, repCmdNotSupported)
		if cmd == cmdUDPAssociate {
			return "", 0, errUDPAssociateUnsupported
		}
		return "", 0, fmt.Errorf("unsupported socks5 command: 0x%02x", cmd)
	}
	if port == 0 {
		_ = writeReply(conn, repGeneralFailure)
		return "", 0, errors.New("invalid target port 0")
	}
	if err := forwarder.ValidateTargetAddr(net.JoinHostPort(host, strconv.Itoa(int(port)))); err != nil {
		_ = writeReply(conn, repHostUnreachable)
		return "", 0, err
	}

	return host, port, nil
}

func writeReply(conn net.Conn, rep byte) error {
	reply := [10]byte{
		socksVersion5,
		rep,
		0x00,     // RSV
		atypIPv4, // BND.ADDR type = IPv4 0.0.0.0:0
		0, 0, 0, 0,
		0, 0,
	}
	_, err := conn.Write(reply[:])
	return err
}

func writeConnectReply(conn net.Conn, localAddr net.Addr) error {
	addr, ok := localAddr.(*net.TCPAddr)
	if !ok {
		return writeReply(conn, repSuccess)
	}
	ip := addr.IP.To4()
	addressType := byte(atypIPv4)
	if ip == nil {
		ip = addr.IP.To16()
		addressType = atypIPv6
	}
	if ip == nil {
		return writeReply(conn, repSuccess)
	}
	reply := append([]byte{socksVersion5, repSuccess, 0x00, addressType}, ip...)
	reply = binary.BigEndian.AppendUint16(reply, uint16(addr.Port))
	_, err := conn.Write(reply)
	return err
}

// isSameEndpoint 判断 (targetHost, targetPort) 是否指向 endpointAddr 同一地址端口（兼容 IPv4/IPv6/localhost 回环等价）。
func isSameEndpoint(targetHost string, targetPort uint16, endpointAddr string) bool {
	if endpointAddr == "" {
		return false
	}
	epHost, epPortStr, err := net.SplitHostPort(endpointAddr)
	if err != nil {
		return false
	}
	epPortNum, err := strconv.ParseUint(epPortStr, 10, 16)
	if err != nil || uint16(epPortNum) != targetPort {
		return false
	}

	targetNorm := normalizeHost(targetHost)
	epNorm := normalizeHost(epHost)
	if targetNorm != "" && strings.EqualFold(targetNorm, epNorm) {
		return true
	}
	if isLoopbackOrUnspecified(targetNorm) && isLoopbackOrUnspecified(epNorm) {
		return true
	}
	return false
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimSuffix(h, ".")
	if ip := net.ParseIP(h); ip != nil {
		return ip.String()
	}
	return strings.ToLower(h)
}

func isLoopbackOrUnspecified(host string) bool {
	if host == "" || strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsUnspecified()
}
