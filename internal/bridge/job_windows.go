//go:build windows

package bridge

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x00002000

	processTerminate = 0x0001
	processSetQuota  = 0x0100
)

var (
	modKernel32                    = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW           = modKernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject    = modKernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject   = modKernel32.NewProc("AssignProcessToJobObject")
	procGenerateConsoleCtrlEvent   = modKernel32.NewProc("GenerateConsoleCtrlEvent")
)

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectExtendedLimitInfo struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

func configurePlatformCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

// bindKillOnCloseJob 创建带 JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 标志的 Windows Job Object 并绑定目标进程。
// 当父进程崩溃或返回的关闭函数被调用时，操作系统内核会自动终止该子进程并释放其驱动句柄。
func bindKillOnCloseJob(pid int) (func() error, error) {
	r1, _, e1 := procCreateJobObjectW.Call(0, 0)
	if r1 == 0 {
		return nil, fmt.Errorf("CreateJobObjectW failed: %w", e1)
	}
	jobHandle := syscall.Handle(r1)

	var info jobObjectExtendedLimitInfo
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose

	r2, _, e2 := procSetInformationJobObject.Call(
		uintptr(jobHandle),
		uintptr(jobObjectExtendedLimitInformation),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
	)
	if r2 == 0 {
		_ = syscall.CloseHandle(jobHandle)
		return nil, fmt.Errorf("SetInformationJobObject failed: %w", e2)
	}

	procHandle, err := syscall.OpenProcess(processSetQuota|processTerminate, false, uint32(pid))
	if err != nil {
		_ = syscall.CloseHandle(jobHandle)
		return nil, fmt.Errorf("OpenProcess(%d) failed: %w", pid, err)
	}
	defer syscall.CloseHandle(procHandle)

	r3, _, e3 := procAssignProcessToJobObject.Call(uintptr(jobHandle), uintptr(procHandle))
	if r3 == 0 {
		_ = syscall.CloseHandle(jobHandle)
		return nil, fmt.Errorf("AssignProcessToJobObject failed: %w", e3)
	}

	var closed bool
	closeFn := func() error {
		if closed {
			return nil
		}
		closed = true
		return syscall.CloseHandle(jobHandle)
	}
	return closeFn, nil
}

// sendGracefulStop 向独立进程组中的 Windows 控制台子进程发送 CTRL_BREAK_EVENT 请求优雅退出。
func sendGracefulStop(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	r1, _, e1 := procGenerateConsoleCtrlEvent.Call(
		uintptr(syscall.CTRL_BREAK_EVENT),
		uintptr(uint32(cmd.Process.Pid)),
	)
	if r1 == 0 {
		return fmt.Errorf("GenerateConsoleCtrlEvent failed: %w", e1)
	}
	return nil
}
