package detector

import (
	"encoding/binary"
	"time"
)

const (
	// DefaultTLSReadTimeout 是识别到 TLS 记录头后继续读取完整 ClientHello 记录的额外超时。
	DefaultTLSReadTimeout = 100 * time.Millisecond
	// MaxTLSRecordInspectSize 是协议窥探阶段允许读取的单个 TLS Record 最大字节数（含 5 字节记录头）。
	MaxTLSRecordInspectSize = 4096

	tlsRecordTypeHandshake  = 0x16
	tlsHandshakeClientHello = 0x01
	tlsExtServerName        = 0x0000
	tlsExtSupportedVersions = 0x002b
	tlsSNIHostNameType      = 0x00

	tlsVerSSL30 = 0x0300
	tlsVer10    = 0x0301
	tlsVer11    = 0x0302
	tlsVer12    = 0x0303
	tlsVer13    = 0x0304
)

// ClientHelloInfo 保存从 TLS ClientHello 中提取的元数据。
type ClientHelloInfo struct {
	SNI        string
	TLSVersion string
	WeakTLS    bool
}

// ParseClientHello 对单条 TLS ClientHello 原始字节执行只读、零错误、容错解析，
// 提取 SNI 域名、最高支持的 TLS 版本及弱加密标记。
// 若数据不完整或格式异常，安全回退并返回已成功解析的部分字段，绝不 panic。
func ParseClientHello(data []byte) ClientHelloInfo {
	var info ClientHelloInfo
	if len(data) < 5 || data[0] != tlsRecordTypeHandshake || data[1] != 0x03 {
		return info
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	payload := data[5:]
	if len(payload) > recordLen {
		payload = payload[:recordLen]
	}

	// Handshake header: 1 byte type + 3 bytes length
	if len(payload) < 4 || payload[0] != tlsHandshakeClientHello {
		return info
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	body := payload[4:]
	if len(body) > hsLen {
		body = body[:hsLen]
	}

	// ClientHello.client_version (2 bytes)
	if len(body) < 2 {
		return info
	}
	legacyVer := binary.BigEndian.Uint16(body[0:2])

	var maxSupportedVer uint16
	// 尝试继续解析 Random(32) + SessionID + CipherSuites + CompressionMethods + Extensions
	if len(body) >= 35 {
		pos := 34 // 2 (version) + 32 (random)

		// Session ID
		sessLen := int(body[pos])
		pos++
		if pos+sessLen <= len(body) {
			pos += sessLen

			// Cipher Suites
			if pos+2 <= len(body) {
				csLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
				pos += 2
				if pos+csLen <= len(body) {
					pos += csLen

					// Compression Methods
					if pos+1 <= len(body) {
						cmLen := int(body[pos])
						pos++
						if pos+cmLen <= len(body) {
							pos += cmLen

							// Extensions (optional)
							if pos+2 <= len(body) {
								extTotalLen := int(binary.BigEndian.Uint16(body[pos : pos+2]))
								pos += 2
								extEnd := pos + extTotalLen
								if extEnd > len(body) {
									extEnd = len(body)
								}
								info.SNI, maxSupportedVer = parseClientHelloExtensions(body[pos:extEnd])
							}
						}
					}
				}
			}
		}
	}

	effectiveVer := maxSupportedVer
	if effectiveVer == 0 && isKnownTLSVersion(legacyVer) {
		effectiveVer = legacyVer
	}
	if effectiveVer != 0 {
		info.TLSVersion, info.WeakTLS = formatTLSVersion(effectiveVer)
	}
	return info
}

func parseClientHelloExtensions(exts []byte) (sni string, maxVer uint16) {
	pos := 0
	for pos+4 <= len(exts) {
		extType := binary.BigEndian.Uint16(exts[pos : pos+2])
		extLen := int(binary.BigEndian.Uint16(exts[pos+2 : pos+4]))
		pos += 4
		if pos+extLen > len(exts) {
			break
		}
		extData := exts[pos : pos+extLen]
		pos += extLen

		switch extType {
		case tlsExtServerName:
			if sni == "" {
				sni = parseSNIExtension(extData)
			}
		case tlsExtSupportedVersions:
			if v := parseSupportedVersionsExtension(extData); v > maxVer {
				maxVer = v
			}
		}
	}
	return sni, maxVer
}

func parseSNIExtension(extData []byte) string {
	if len(extData) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(extData[0:2]))
	listEnd := 2 + listLen
	if listEnd > len(extData) {
		listEnd = len(extData)
	}
	pos := 2
	for pos+3 <= listEnd {
		nameType := extData[pos]
		nameLen := int(binary.BigEndian.Uint16(extData[pos+1 : pos+3]))
		pos += 3
		if pos+nameLen > listEnd {
			break
		}
		if nameType == tlsSNIHostNameType && nameLen > 0 {
			host := string(extData[pos : pos+nameLen])
			if isValidSNIHost(host) {
				return host
			}
		}
		pos += nameLen
	}
	return ""
}

func parseSupportedVersionsExtension(extData []byte) uint16 {
	if len(extData) < 3 {
		return 0
	}
	vLen := int(extData[0])
	if vLen < 2 || vLen%2 != 0 || 1+vLen > len(extData) {
		return 0
	}
	var maxVer uint16
	for i := 1; i+1 < 1+vLen; i += 2 {
		ver := binary.BigEndian.Uint16(extData[i : i+2])
		if isKnownTLSVersion(ver) && ver > maxVer {
			maxVer = ver
		}
	}
	return maxVer
}

func isKnownTLSVersion(v uint16) bool {
	switch v {
	case tlsVerSSL30, tlsVer10, tlsVer11, tlsVer12, tlsVer13:
		return true
	default:
		return false
	}
}

func formatTLSVersion(v uint16) (label string, weak bool) {
	switch v {
	case tlsVer13:
		return "TLS 1.3", false
	case tlsVer12:
		return "TLS 1.2", false
	case tlsVer11:
		return "TLS 1.1", true
	case tlsVer10:
		return "TLS 1.0", true
	case tlsVerSSL30:
		return "SSL 3.0", true
	default:
		return "", false
	}
}

func isValidSNIHost(host string) bool {
	if len(host) == 0 || len(host) > 255 {
		return false
	}
	for i := 0; i < len(host); i++ {
		b := host[i]
		if b <= 0x20 || b >= 0x7f {
			return false
		}
	}
	return true
}
