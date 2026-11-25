//go:build windows

package cert

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	certStoreProvSystemW         = uintptr(10)
	certStoreProvSystemRegistryW = uintptr(13)
	certSystemStoreCurrentUser   = uint32(0x00010000)
	certSystemStoreLocalMachine  = uint32(0x00020000)
	certStoreOpenExistingFlag    = uint32(0x00004000)
	certStoreReadonlyFlag        = uint32(0x00008000)
	certStoreAddReplaceExisting  = uint32(3)
	certEncodingX509AndPKCS7     = uint32(syscall.X509_ASN_ENCODING | syscall.PKCS_7_ASN_ENCODING)
	cryptENotFound               = syscall.Errno(0x80092004)
)

var (
	modCrypt32                           = syscall.NewLazyDLL("crypt32.dll")
	procCertOpenStore                    = modCrypt32.NewProc("CertOpenStore")
	procCertAddEncodedCertificateToStore = modCrypt32.NewProc("CertAddEncodedCertificateToStore")
	procCertDuplicateCertificateContext  = modCrypt32.NewProc("CertDuplicateCertificateContext")
	procCertDeleteCertificateFromStore   = modCrypt32.NewProc("CertDeleteCertificateFromStore")
)

type windowsCertStore struct{}

// NewSystemStore 返回基于 Windows crypt32.dll 的系统受信任根证书存储实现。
func NewSystemStore() Store {
	return windowsCertStore{}
}

type storeLocation struct {
	name string
	flag uint32
}

var rootStoreLocations = []storeLocation{
	{name: "LocalMachine", flag: certSystemStoreLocalMachine},
	{name: "CurrentUser", flag: certSystemStoreCurrentUser},
}

func openRootStore(provider uintptr, locationFlag uint32, readOnly, existingOnly bool) (syscall.Handle, error) {
	rootName, err := syscall.UTF16PtrFromString("Root")
	if err != nil {
		return 0, err
	}
	flags := locationFlag
	if existingOnly {
		flags |= certStoreOpenExistingFlag
	}
	if readOnly {
		flags |= certStoreReadonlyFlag
	}
	h, _, callErr := procCertOpenStore.Call(
		provider,
		0,
		0,
		uintptr(flags),
		uintptr(unsafe.Pointer(rootName)),
	)
	runtime.KeepAlive(rootName)
	if h == 0 {
		return 0, fmt.Errorf("CertOpenStore(Root) failed: %w", callErr)
	}
	return syscall.Handle(h), nil
}

func enumerateRootCertificates(store syscall.Handle, visit func(*syscall.CertContext) bool) error {
	var prevCtx *syscall.CertContext
	for {
		ctx, err := syscall.CertEnumCertificatesInStore(store, prevCtx)
		if ctx == nil {
			if errors.Is(err, cryptENotFound) || errors.Is(err, syscall.ERROR_NO_MORE_FILES) {
				return nil
			}
			return err
		}
		if !visit(ctx) {
			return syscall.CertFreeCertificateContext(ctx)
		}
		prevCtx = ctx
	}
}

func (windowsCertStore) Inspect(fingerprintSHA1 string) (bool, []string, int, error) {
	wantFP := strings.ToUpper(strings.TrimSpace(fingerprintSHA1))
	var matchedScopes []string
	legacyFingerprints := make(map[string]struct{})
	var inspectErr error
	machineMatched := false

	for _, loc := range rootStoreLocations {
		storeHandle, err := openRootStore(certStoreProvSystemW, loc.flag, true, true)
		if err != nil {
			inspectErr = errors.Join(inspectErr, fmt.Errorf("open %s root store: %w", loc.name, err))
			continue
		}

		locMatched := false
		err = enumerateRootCertificates(storeHandle, func(ctx *syscall.CertContext) bool {
			if ctx.EncodedCert == nil || ctx.Length == 0 {
				return true
			}
			raw := unsafe.Slice(ctx.EncodedCert, int(ctx.Length))
			sum := sha1.Sum(raw)
			fp := strings.ToUpper(hex.EncodeToString(sum[:]))

			if wantFP != "" && fp == wantFP {
				locMatched = true
				legacyFingerprints[fp] = struct{}{}
			} else if parsed, parseErr := x509.ParseCertificate(raw); parseErr == nil && isPortSwiggerCert(parsed) {
				legacyFingerprints[fp] = struct{}{}
			}
			return true
		})
		_ = syscall.CertCloseStore(storeHandle, 0)
		if err != nil {
			inspectErr = errors.Join(inspectErr, fmt.Errorf("inspect %s root store: %w", loc.name, err))
		}

		if loc.flag == certSystemStoreLocalMachine {
			machineMatched = locMatched
		} else if locMatched && machineMatched {
			// CurrentUser's logical Root includes LocalMachine. Count a separate
			// CurrentUser installation only if its own writable registry store matches.
			locMatched, err = hasMatchInRootStore(certStoreProvSystemRegistryW, loc.flag, func(ctx *syscall.CertContext) bool {
				return matchesFingerprint(ctx, wantFP)
			})
			if err != nil {
				inspectErr = errors.Join(inspectErr, fmt.Errorf("inspect separate CurrentUser root store: %w", err))
			}
		}
		if locMatched {
			matchedScopes = append(matchedScopes, loc.name)
		}
	}

	return len(matchedScopes) > 0, matchedScopes, len(legacyFingerprints), inspectErr
}

func (windowsCertStore) InstallRootCA(rawDER []byte, preferMachine bool) (string, error) {
	if len(rawDER) == 0 {
		return "", fmt.Errorf("empty DER payload")
	}

	if preferMachine {
		if err := addDERToRootStore(certSystemStoreLocalMachine, rawDER); err == nil {
			return "LocalMachine", nil
		}
	}

	if err := addDERToRootStore(certSystemStoreCurrentUser, rawDER); err != nil {
		return "", err
	}
	return "CurrentUser", nil
}

func addDERToRootStore(locationFlag uint32, rawDER []byte) error {
	storeHandle, err := openRootStore(certStoreProvSystemRegistryW, locationFlag, false, false)
	if err != nil {
		return err
	}
	defer syscall.CertCloseStore(storeHandle, 0)

	r1, _, callErr := procCertAddEncodedCertificateToStore.Call(
		uintptr(storeHandle),
		uintptr(certEncodingX509AndPKCS7),
		uintptr(unsafe.Pointer(&rawDER[0])),
		uintptr(uint32(len(rawDER))),
		uintptr(certStoreAddReplaceExisting),
		0,
	)
	runtime.KeepAlive(rawDER)
	if r1 == 0 {
		return fmt.Errorf("CertAddEncodedCertificateToStore failed: %w", callErr)
	}
	return nil
}

func (windowsCertStore) RemoveBurpCAs(fingerprintSHA1 string, isAdmin bool) (int, string, error) {
	wantFP := strings.ToUpper(strings.TrimSpace(fingerprintSHA1))
	totalRemoved := 0
	var warnings []string
	var removeErr error
	match := func(ctx *syscall.CertContext) bool { return shouldRemoveCertContext(ctx, wantFP) }

	for _, loc := range rootStoreLocations {
		if loc.flag == certSystemStoreLocalMachine && !isAdmin {
			continue
		}

		storeHandle, err := openRootStore(certStoreProvSystemRegistryW, loc.flag, false, true)
		if err != nil {
			if !isMissingRootStore(err) {
				removeErr = errors.Join(removeErr, fmt.Errorf("无法写入 %s 证书库: %w", loc.name, err))
			}
			continue
		}

		// 先复制待删除的证书上下文句柄，遍历结束后再统一调用 CertDeleteCertificateFromStore，避免破坏枚举游标
		var toDelete []uintptr
		err = enumerateRootCertificates(storeHandle, func(ctx *syscall.CertContext) bool {
			if match(ctx) {
				dup, _, dupErr := procCertDuplicateCertificateContext.Call(uintptr(unsafe.Pointer(ctx)))
				if dup != 0 {
					toDelete = append(toDelete, dup)
				} else {
					removeErr = errors.Join(removeErr, fmt.Errorf("复制 %s 证书上下文: %w", loc.name, dupErr))
				}
			}
			return true
		})
		if err != nil {
			removeErr = errors.Join(removeErr, fmt.Errorf("枚举 %s 证书库: %w", loc.name, err))
		}

		for _, dupPtr := range toDelete {
			// 注意：无论成功或失败，CertDeleteCertificateFromStore 均会释放传入的上下文句柄
			ok, _, deleteErr := procCertDeleteCertificateFromStore.Call(dupPtr)
			if ok != 0 {
				totalRemoved++
			} else {
				removeErr = errors.Join(removeErr, fmt.Errorf("删除 %s 根证书: %w", loc.name, deleteErr))
			}
		}
		_ = syscall.CertCloseStore(storeHandle, 0)
	}

	for _, loc := range rootStoreLocations {
		remaining, err := hasMatchInRootStore(certStoreProvSystemW, loc.flag, match)
		if err != nil {
			removeErr = errors.Join(removeErr, fmt.Errorf("确认 %s 证书卸载结果: %w", loc.name, err))
			continue
		}
		if remaining {
			if loc.flag == certSystemStoreLocalMachine && !isAdmin {
				warnings = append(warnings, "系统级存储区 (LocalMachine) 中仍有匹配的根证书，当前权限无法清理")
			} else {
				warnings = append(warnings, fmt.Sprintf("%s 信任范围内仍有匹配的根证书", loc.name))
			}
		}
	}
	if removeErr == nil && len(warnings) > 0 {
		removeErr = ErrCleanupIncomplete
	}
	return totalRemoved, strings.Join(warnings, "；"), removeErr
}

func isMissingRootStore(err error) bool {
	return errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) || errors.Is(err, syscall.ERROR_PATH_NOT_FOUND) || errors.Is(err, cryptENotFound)
}

func hasMatchInRootStore(provider uintptr, locationFlag uint32, match func(*syscall.CertContext) bool) (bool, error) {
	storeHandle, err := openRootStore(provider, locationFlag, true, true)
	if err != nil {
		if provider == certStoreProvSystemRegistryW && isMissingRootStore(err) {
			return false, nil
		}
		return false, err
	}
	defer syscall.CertCloseStore(storeHandle, 0)

	found := false
	err = enumerateRootCertificates(storeHandle, func(ctx *syscall.CertContext) bool {
		found = match(ctx)
		return !found
	})
	return found, err
}

func matchesFingerprint(ctx *syscall.CertContext, wantFP string) bool {
	if wantFP == "" || ctx.EncodedCert == nil || ctx.Length == 0 {
		return false
	}
	sum := sha1.Sum(unsafe.Slice(ctx.EncodedCert, int(ctx.Length)))
	return strings.EqualFold(hex.EncodeToString(sum[:]), wantFP)
}

func shouldRemoveCertContext(ctx *syscall.CertContext, wantFP string) bool {
	if ctx == nil || ctx.EncodedCert == nil || ctx.Length == 0 {
		return false
	}
	if matchesFingerprint(ctx, wantFP) {
		return true
	}
	raw := unsafe.Slice(ctx.EncodedCert, int(ctx.Length))
	if parsed, err := x509.ParseCertificate(raw); err == nil && isPortSwiggerCert(parsed) {
		return true
	}
	return false
}
