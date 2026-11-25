//go:build windows

package bridge

import (
	"syscall"
	"unsafe"
)

const tokenElevationInfoClass = 20

type tokenElevation struct {
	TokenIsElevated uint32
}

// IsProcessAdmin 检测当前 Windows 进程是否具备已提权的管理员令牌权限。
func IsProcessAdmin() bool {
	tok, err := syscall.OpenCurrentProcessToken()
	if err == nil {
		defer tok.Close()
		var elev tokenElevation
		var retLen uint32
		err = syscall.GetTokenInformation(
			tok,
			tokenElevationInfoClass,
			(*byte)(unsafe.Pointer(&elev)),
			uint32(unsafe.Sizeof(elev)),
			&retLen,
		)
		if err == nil {
			return elev.TokenIsElevated != 0
		}
	}

	// 兜底检测：尝试只读打开物理磁盘句柄 \\.\PHYSICALDRIVE0（仅管理员成功）
	pathPtr, err := syscall.UTF16PtrFromString(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return false
	}
	h, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return false
	}
	_ = syscall.CloseHandle(h)
	return true
}
