//go:build !windows

package bridge

// IsProcessAdmin 在非 Windows 平台固定返回 false。
func IsProcessAdmin() bool {
	return false
}
