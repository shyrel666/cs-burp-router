package bridge

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultLogCapacity 是子进程引擎输出保留的最大日志行数。
	DefaultLogCapacity = 200
	// DefaultStartTimeout bounds the wait for the ProxyBridge engine to become ready.
	DefaultStartTimeout = 10 * time.Second
	// DefaultStopTimeout 是停止子进程时等待优雅退出的默认超时时间。
	DefaultStopTimeout = 3 * time.Second
)

// ErrAlreadyRunning 表示 ProxyBridge 子进程已在运行中。
var ErrAlreadyRunning = errors.New("ProxyBridge process is already running")

// ErrManagerClosed 表示托管器已关闭，不能再启动子进程。
var ErrManagerClosed = errors.New("ProxyBridge manager is closed")

// ErrAdminRequired 表示启动 Windows ProxyBridge 引擎需要管理员权限。
var ErrAdminRequired = errors.New("administrator privileges are required to start ProxyBridge on Windows")

// State 表示 ProxyBridge 托管运行状态。
type State string

const (
	StateStopped  State = "Stopped"
	StateStarting State = "Starting"
	StateRunning  State = "Running"
	StateError    State = "Error"
)

// StatusSnapshot 表示 ProxyBridge 托管器的实时状态快照。
type StatusSnapshot struct {
	State         State    `json:"state"`
	IsAdmin       bool     `json:"is_admin"`
	Processes     []string `json:"processes"`
	TargetDomains string   `json:"targetDomains"`
	BinaryPath    string   `json:"binaryPath"`
	ProfilePath   string   `json:"profilePath,omitempty"`
	PID           int      `json:"pid"`
	LastError     string   `json:"lastError"`
	Logs          []string `json:"logs"`
}

// StartOptions 定义启动或热重启 ProxyBridge 时的参数。
type StartOptions struct {
	Processes     []string
	TargetDomains *string
}

// ManagedProcess 抽象受控运行的子进程句柄，支持注入 Mock 实现以进行无外部依赖单元测试。
type ManagedProcess interface {
	PID() int
	Stdout() io.Reader
	Stderr() io.Reader
	Terminate() error
	Kill() error
	Wait() error
}

// Runner 定义创建并启动子进程的工厂函数签名。
type Runner func(binaryPath string, args []string) (ManagedProcess, error)

// LogBuffer 是固定行数的并发安全环形日志缓冲区。
type LogBuffer struct {
	mu       sync.RWMutex
	capacity int
	buf      []string
	head     int
	count    int
}

// NewLogBuffer 创建指定行数上限的环形日志缓冲区。
func NewLogBuffer(capacity int) *LogBuffer {
	if capacity <= 0 {
		capacity = DefaultLogCapacity
	}
	return &LogBuffer{
		capacity: capacity,
		buf:      make([]string, capacity),
	}
}

// Append 追加一行日志，超出容量时自动覆盖最早一行。
func (b *LogBuffer) Append(line string) {
	b.mu.Lock()
	b.buf[b.head] = line
	b.head = (b.head + 1) % b.capacity
	if b.count < b.capacity {
		b.count++
	}
	b.mu.Unlock()
}

// Lines 按时间正序（从旧到新）返回缓冲区内所有日志行的副本。
func (b *LogBuffer) Lines() []string {
	b.mu.RLock()
	out := make([]string, b.count)
	start := 0
	if b.count == b.capacity {
		start = b.head
	}
	for i := 0; i < b.count; i++ {
		out[i] = b.buf[(start+i)%b.capacity]
	}
	b.mu.RUnlock()
	return out
}

// Clear 清空日志缓冲区。
func (b *LogBuffer) Clear() {
	b.mu.Lock()
	clear(b.buf)
	b.head = 0
	b.count = 0
	b.mu.Unlock()
}

// ManagerConfig 定义 ProxyBridge 子进程托管器的配置。
type ManagerConfig struct {
	// BinaryPath 为可选的自定义 ProxyBridge_CLI.exe 路径（对应 -bridge-bin）。
	BinaryPath string
	// SocksAddr 为本地 SOCKS5 监听地址（用于生成 .pbprofile）。
	SocksAddr string
	// TempDir 为可选的临时 .pbprofile 存放目录，为空则使用系统临时目录。
	TempDir string
	// StartTimeout limits the wait for the real CLI's readiness message.
	StartTimeout time.Duration
	// StopTimeout 为停止子进程前等待优雅退出的超时时间，<=0 时默认 3s。
	StopTimeout time.Duration
	// LogCapacity 为引擎环形日志保留行数，<=0 时默认 200。
	LogCapacity int
	// Runner 为可选的进程启动器；为空时使用真实系统进程启动器（含 HideWindow 与 Job Object）。
	Runner Runner
	// AdminChecker 为可选的管理员权限检测函数；为空时默认使用 IsProcessAdmin。
	AdminChecker func() bool
	// SkipBinaryLookup 在使用纯内存 Mock Runner 测试时可设为 true，跳过磁盘可执行文件存在性检查。
	SkipBinaryLookup bool
	// Logger 为可选宿主日志器。
	Logger *log.Logger
}

type runningInstance struct {
	proc        ManagedProcess
	profilePath string
	stopping    atomic.Bool
	doneCh      chan struct{}
	startupErr  error // protected by Manager.mu
	waitErr     error // read after doneCh closes
}

// Manager 负责 .pbprofile 动态生成与 ProxyBridge_CLI.exe 全生命周期托管。
type Manager struct {
	customBin        string
	socksAddr        string
	tempDir          string
	startTimeout     time.Duration
	stopTimeout      time.Duration
	runner           Runner
	waitForReady     bool
	requiresAdmin    bool
	adminChecker     func() bool
	skipBinaryLookup bool
	logger           *log.Logger
	logs             *LogBuffer

	opMu   sync.Mutex
	closed bool

	mu            sync.RWMutex
	state         State
	processes     []string
	targetDomains string
	resolvedBin   string
	profilePath   string
	pid           int
	lastError     string
	current       *runningInstance
}

// NewManager 创建并发安全的 ProxyBridge 进程托管器。
func NewManager(cfg ManagerConfig) *Manager {
	startTimeout := cfg.StartTimeout
	if startTimeout <= 0 {
		startTimeout = DefaultStartTimeout
	}
	stopTimeout := cfg.StopTimeout
	if stopTimeout <= 0 {
		stopTimeout = DefaultStopTimeout
	}
	runner := cfg.Runner
	if runner == nil {
		runner = defaultExecRunner
	}
	adminChecker := cfg.AdminChecker
	if adminChecker == nil {
		adminChecker = IsProcessAdmin
	}

	resolved := cfg.BinaryPath
	if !cfg.SkipBinaryLookup {
		if bin, err := ResolveBinaryPath(cfg.BinaryPath); err == nil {
			resolved = bin
		}
	}

	socksAddr := cfg.SocksAddr
	if socksAddr == "" {
		socksAddr = "127.0.0.1:10808"
	}

	return &Manager{
		customBin:        cfg.BinaryPath,
		socksAddr:        socksAddr,
		tempDir:          cfg.TempDir,
		startTimeout:     startTimeout,
		stopTimeout:      stopTimeout,
		runner:           runner,
		waitForReady:     cfg.Runner == nil,
		requiresAdmin:    runtime.GOOS == "windows" && cfg.Runner == nil,
		adminChecker:     adminChecker,
		skipBinaryLookup: cfg.SkipBinaryLookup,
		logger:           cfg.Logger,
		logs:             NewLogBuffer(cfg.LogCapacity),
		state:            StateStopped,
		processes:        []string{},
		targetDomains:    "*",
		resolvedBin:      resolved,
	}
}

// ResolveBinaryPath 按优先级定位 ProxyBridge_CLI.exe：
// 1. 显式传入的 customPath（如 -bridge-bin）；
// 2. 当前可执行文件所在目录及其下的 third_party/proxybridge/ProxyBridge_CLI.exe；
func ResolveBinaryPath(customPath string) (string, error) {
	if trimmed := strings.TrimSpace(customPath); trimmed != "" {
		if ok, abs := checkRegularFile(trimmed); ok {
			return abs, nil
		}
		return "", fmt.Errorf("custom ProxyBridge_CLI binary not found at %q", trimmed)
	}

	var candidates []string
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		candidates = append(candidates,
			filepath.Join(exeDir, "ProxyBridge_CLI.exe"),
			filepath.Join(exeDir, "third_party", "proxybridge", "ProxyBridge_CLI.exe"),
		)
	}
	for _, c := range candidates {
		if ok, abs := checkRegularFile(c); ok {
			return abs, nil
		}
	}
	return "", errors.New("ProxyBridge_CLI.exe not found (checked executable directory and third_party/proxybridge/ProxyBridge_CLI.exe)")
}

func checkRegularFile(p string) (bool, string) {
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() {
		return false, ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		return true, abs
	}
	return true, p
}

// Start 使用默认 TargetDomains ("*") 启动 ProxyBridge 接管给定目标进程列表。
// 若当前已在运行中则返回 ErrAlreadyRunning。
func (m *Manager) Start(processes []string) error {
	return m.StartWithOptions(StartOptions{
		Processes: processes,
	})
}

// StartWithOptions 按给定进程列表与可选 TargetDomains 生成临时 .pbprofile 并启动 ProxyBridge_CLI.exe。
func (m *Manager) StartWithOptions(opts StartOptions) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.startLocked(opts, false)
}

// Restart 停止当前运行实例（如有），并使用新目标进程列表重新生成配置启动。
func (m *Manager) Restart(processes []string) error {
	return m.RestartWithOptions(StartOptions{
		Processes: processes,
	})
}

// RestartWithOptions 停止当前运行实例（如有），并使用给定参数重新启动。
func (m *Manager) RestartWithOptions(opts StartOptions) error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.startLocked(opts, true)
}

// Stop 安全终止正在运行的 ProxyBridge 子进程（先优雅终止，超时则强杀）并清理临时 .pbprofile 文件。
func (m *Manager) Stop() error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.stopLocked()
}

// Shutdown 永久拒绝后续启动请求，并停止当前运行的子进程。
func (m *Manager) Shutdown() error {
	m.opMu.Lock()
	defer m.opMu.Unlock()
	m.closed = true
	return m.stopLocked()
}

// Status 返回当前托管状态、目标进程、CLI 路径、PID 及最近 200 行日志快照（并发安全）。
func (m *Manager) Status() StatusSnapshot {
	m.mu.RLock()
	procs := make([]string, len(m.processes))
	copy(procs, m.processes)
	snap := StatusSnapshot{
		State:         m.state,
		IsAdmin:       m.adminChecker(),
		Processes:     procs,
		TargetDomains: m.targetDomains,
		BinaryPath:    m.resolvedBin,
		ProfilePath:   m.profilePath,
		PID:           m.pid,
		LastError:     m.lastError,
	}
	m.mu.RUnlock()

	snap.Logs = m.logs.Lines()
	if snap.Logs == nil {
		snap.Logs = []string{}
	}
	return snap
}

func (m *Manager) startLocked(opts StartOptions, restart bool) error {
	if m.closed {
		return ErrManagerClosed
	}
	m.mu.RLock()
	alreadyRunning := m.current != nil
	m.mu.RUnlock()
	if alreadyRunning && !restart {
		return ErrAlreadyRunning
	}
	if m.requiresAdmin && !m.adminChecker() {
		return ErrAdminRequired
	}

	binPath := m.customBin
	if !m.skipBinaryLookup {
		resolved, err := ResolveBinaryPath(m.customBin)
		if err != nil {
			if !alreadyRunning {
				m.setErrorState(err)
			}
			return err
		}
		binPath = resolved
	} else if binPath == "" {
		binPath = "mock-ProxyBridge_CLI.exe"
	}

	profile, err := BuildProfile(ProfileOptions{
		SocksAddr:     m.socksAddr,
		Processes:     opts.Processes,
		TargetDomains: opts.TargetDomains,
	})
	if err != nil {
		return err
	}

	cleanedProcs := make([]string, 0, len(profile.ProxyRules))
	for _, r := range profile.ProxyRules {
		if strings.EqualFold(r.ProcessName, filepath.Base(binPath)) {
			return fmt.Errorf("cannot proxy the configured ProxyBridge executable: %s", r.ProcessName)
		}
		cleanedProcs = append(cleanedProcs, r.ProcessName)
	}
	targetDomains := "*"
	if opts.TargetDomains != nil {
		targetDomains = *opts.TargetDomains
	}

	profilePath, err := WriteTempProfile(m.tempDir, profile)
	if err != nil {
		if !alreadyRunning {
			m.setErrorState(err)
		}
		return err
	}
	if restart && alreadyRunning {
		if err := m.stopLocked(); err != nil {
			_ = os.Remove(profilePath)
			return err
		}
	}

	args := []string{"--profile", profilePath, "--verbose", "3"}
	proc, err := m.runner(binPath, args)
	if err != nil {
		_ = os.Remove(profilePath)
		startErr := fmt.Errorf("start ProxyBridge_CLI: %w", err)
		m.setErrorState(startErr)
		return startErr
	}

	inst := &runningInstance{
		proc:        proc,
		profilePath: profilePath,
		doneCh:      make(chan struct{}),
	}

	m.logs.Append(fmt.Sprintf(
		"[bridge] started PID=%d processes=%v targetDomains=%q profile=%s",
		proc.PID(),
		cleanedProcs,
		targetDomains,
		profilePath,
	))

	m.mu.Lock()
	m.current = inst
	if m.waitForReady {
		m.state = StateStarting
	} else {
		m.state = StateRunning
	}
	m.processes = cleanedProcs
	m.targetDomains = targetDomains
	m.resolvedBin = binPath
	m.profilePath = profilePath
	m.pid = proc.PID()
	m.lastError = ""
	m.mu.Unlock()

	ready := make(chan struct{}, 1)
	stdout, stderr := proc.Stdout(), proc.Stderr()
	var logWg sync.WaitGroup
	if stdout != nil {
		logWg.Add(1)
		go func() {
			defer logWg.Done()
			m.captureStream("[stdout] ", stdout, ready)
		}()
	}
	if stderr != nil {
		logWg.Add(1)
		go func() {
			defer logWg.Done()
			m.captureStream("[stderr] ", stderr, nil)
		}()
	}

	go func(ri *runningInstance) {
		defer close(ri.doneCh)
		ri.waitErr = ri.proc.Wait()
		// A descendant can retain an inherited writer after the CLI exits.
		drainTimer := time.AfterFunc(min(m.stopTimeout/2, 250*time.Millisecond), func() {
			closeOutput(stdout)
			closeOutput(stderr)
		})
		logWg.Wait()
		drainTimer.Stop()
		_ = os.Remove(ri.profilePath)

		m.mu.Lock()
		if m.current == ri {
			m.current = nil
			m.pid = 0
			m.profilePath = ""
			if ri.startupErr != nil {
				m.state = StateError
				m.lastError = ri.startupErr.Error()
			} else if ri.stopping.Load() {
				m.state = StateStopped
				m.lastError = ""
			} else if ri.waitErr != nil {
				m.state = StateError
				m.lastError = fmt.Sprintf("ProxyBridge_CLI exited unexpectedly: %v", ri.waitErr)
				m.logs.Append("[bridge] " + m.lastError)
			} else {
				m.state = StateStopped
				m.lastError = ""
				m.logs.Append("[bridge] process exited normally")
			}
		}
		m.mu.Unlock()
	}(inst)

	if m.waitForReady {
		if err := m.waitUntilReady(inst, ready); err != nil {
			return err
		}
	}
	if m.logger != nil {
		m.logger.Printf("ProxyBridge started (pid=%d, processes=%v)", proc.PID(), cleanedProcs)
	}
	return nil
}

func (m *Manager) waitUntilReady(inst *runningInstance, ready <-chan struct{}) error {
	select {
	case <-ready:
		m.mu.Lock()
		if m.current == inst {
			m.state = StateRunning
			m.mu.Unlock()
			return nil
		}
		m.mu.Unlock()
		// Exit has already cleared the current instance.
		<-inst.doneCh
	case <-inst.doneCh:
	case <-time.After(m.startTimeout):
		startErr := fmt.Errorf("ProxyBridge was not ready within %s", m.startTimeout)
		m.mu.Lock()
		inst.startupErr = startErr
		m.mu.Unlock()
		stopErr := m.stopLocked()
		if stopErr == nil {
			m.setErrorState(startErr)
		}
		return errors.Join(startErr, stopErr)
	}
	err := errors.New("ProxyBridge exited before it was ready")
	if inst.waitErr != nil {
		err = fmt.Errorf("ProxyBridge exited before it was ready: %w", inst.waitErr)
	}
	m.setErrorState(err)
	return err
}

func (m *Manager) stopLocked() error {
	m.mu.RLock()
	inst := m.current
	m.mu.RUnlock()

	if inst == nil {
		m.mu.Lock()
		m.state = StateStopped
		m.pid = 0
		m.profilePath = ""
		m.lastError = ""
		m.mu.Unlock()
		return nil
	}

	inst.stopping.Store(true)
	terminateErr := inst.proc.Terminate()
	if terminateErr == nil {
		select {
		case <-inst.doneCh:
			return m.reportStopped()
		case <-time.After(m.stopTimeout):
			m.logs.Append("[bridge] graceful stop timed out, forcing kill...")
		}
	}

	killErr := inst.proc.Kill()
	select {
	case <-inst.doneCh:
		return m.reportStopped()
	case <-time.After(m.stopTimeout):
		err := errors.Join(fmt.Errorf("ProxyBridge did not exit after forced stop within %s", m.stopTimeout), terminateErr, killErr)
		m.mu.Lock()
		if m.current == inst {
			m.state = StateError
			m.lastError = err.Error()
		}
		m.mu.Unlock()
		m.logs.Append("[bridge] error: " + err.Error())
		return err
	}
}

func (m *Manager) reportStopped() error {
	m.logs.Append("[bridge] stopped")
	if m.logger != nil {
		m.logger.Printf("ProxyBridge stopped")
	}
	return nil
}

func (m *Manager) setErrorState(err error) {
	m.mu.Lock()
	m.state = StateError
	m.lastError = err.Error()
	m.pid = 0
	m.mu.Unlock()
	m.logs.Append("[bridge] error: " + err.Error())
}

func (m *Manager) captureStream(prefix string, r io.Reader, ready chan<- struct{}) {
	defer closeOutput(r)
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 256*1024)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r\n")
		if strings.TrimSpace(line) == "" {
			continue
		}
		m.logs.Append(prefix + line)
		// Version 4.3.0 flushes the core log even when standard output is a pipe.
		if ready != nil && (line == "[LOG]  ProxyBridge started" || line == "ProxyBridge is running. Press Ctrl+C to stop.") {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
	}
	if err := scanner.Err(); err != nil {
		m.logs.Append(prefix + "read output: " + err.Error())
		_, _ = io.Copy(io.Discard, r)
	}
}

func closeOutput(r io.Reader) {
	if closer, ok := r.(io.Closer); ok {
		_ = closer.Close()
	}
}

type osExecProcess struct {
	cmd      *exec.Cmd
	stdout   io.ReadCloser
	stderr   io.ReadCloser
	closeJob func() error
	jobMu    sync.Mutex
}

func defaultExecRunner(binaryPath string, args []string) (ManagedProcess, error) {
	cmd := exec.Command(binaryPath, args...)
	configurePlatformCmd(cmd)

	// Own the read ends so cmd.Wait can reap the process before all output is read.
	stdout, stdoutWriter, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	defer stdoutWriter.Close()
	stderr, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdout.Close()
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}
	defer stderrWriter.Close()
	cmd.Stdout = stdoutWriter
	cmd.Stderr = stderrWriter

	if err := cmd.Start(); err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, err
	}

	closeJob, jobErr := bindKillOnCloseJob(cmd.Process.Pid)
	if jobErr != nil {
		// 若极端受限沙箱拒绝嵌套 Job Object，不阻断运行，仍保留常规进程控制与超时 Kill
		closeJob = func() error { return nil }
	}

	return &osExecProcess{
		cmd:      cmd,
		stdout:   stdout,
		stderr:   stderr,
		closeJob: closeJob,
	}, nil
}

func (p *osExecProcess) PID() int {
	if p.cmd != nil && p.cmd.Process != nil {
		return p.cmd.Process.Pid
	}
	return 0
}

func (p *osExecProcess) Stdout() io.Reader { return p.stdout }
func (p *osExecProcess) Stderr() io.Reader { return p.stderr }

func (p *osExecProcess) Terminate() error {
	return sendGracefulStop(p.cmd)
}

func (p *osExecProcess) Kill() error {
	var killErr error
	if p.cmd != nil && p.cmd.Process != nil {
		killErr = p.cmd.Process.Kill()
	}
	p.releaseJob()
	return killErr
}

func (p *osExecProcess) Wait() error {
	err := p.cmd.Wait()
	p.releaseJob()
	return err
}

func (p *osExecProcess) releaseJob() {
	p.jobMu.Lock()
	defer p.jobMu.Unlock()
	if p.closeJob != nil {
		_ = p.closeJob()
		p.closeJob = nil
	}
}
