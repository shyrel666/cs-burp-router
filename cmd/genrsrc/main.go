// Command genrsrc 生成供 Go 链接器自动内嵌的 Windows x64 COFF 资源对象文件 (.syso)，
// 将应用图标 (RT_ICON / RT_GROUP_ICON)、管理员 UAC 清单 (RT_MANIFEST) 与标准 PE 文件版本属性 (RT_VERSION) 直接编译进可执行文件。
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"unicode/utf16"
)

const (
	imageFileMachineAMD64      = 0x8664
	imageScnCntInitializedData = 0x00000040
	imageScnMemRead            = 0x40000000
	imageRelAMD64Addr32NB      = 0x0003
	imageSymClassStatic        = 3
	rtIcon                     = 3
	rtGroupIcon                = 14
	rtVersion                  = 16
	rtManifest                 = 24
	langZhCN                   = 0x0804
	langEnUS                   = 0x0409
	codePageUTF16LE            = 0x04b0
)

func main() {
	manifestPath := flag.String("manifest", "packaging/cs-burp-router.exe.manifest", "Path to application XML manifest")
	iconPath := flag.String("icon", "packaging/cs-burp-router.ico", "Optional path to application .ico file")
	outPath := flag.String("out", "cmd/router/rsrc_windows_amd64.syso", "Output .syso file path")
	versionStr := flag.String("version", "1.0.0.0", "Four-part version string")
	genAssets := flag.Bool("gen-assets", false, "Regenerate SVG, PNG, ICO, and Web favicon assets from vector definition")
	flag.Parse()

	if *genAssets {
		if err := writeAllBrandAssets(); err != nil {
			fmt.Fprintf(os.Stderr, "generate brand assets: %v\n", err)
			os.Exit(1)
		}
	}

	manifestBytes, err := os.ReadFile(*manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read manifest %s: %v\n", *manifestPath, err)
		os.Exit(1)
	}

	var icoBytes []byte
	if *iconPath != "" {
		icoBytes, err = os.ReadFile(*iconPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read icon %s: %v\n", *iconPath, err)
			os.Exit(1)
		}
	}

	versionBlob := buildVSVersionInfo(*versionStr)
	sysoBytes, err := buildCOFFResourceObject(versionBlob, manifestBytes, icoBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build coff resource: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outPath, sysoBytes, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write syso %s: %v\n", *outPath, err)
		os.Exit(1)
	}
}

func writeAllBrandAssets() error {
	png512, err := encodePNGBytes(renderLogoNRGBA(512))
	if err != nil {
		return fmt.Errorf("encode 512px png: %w", err)
	}
	appICO, err := buildICOBytes([]int{48, 32, 24, 16, 64, 256})
	if err != nil {
		return fmt.Errorf("encode app ico: %w", err)
	}
	favICO, err := buildICOBytes([]int{48, 32, 16})
	if err != nil {
		return fmt.Errorf("encode favicon ico: %w", err)
	}

	targets := []struct {
		path string
		data []byte
	}{
		{"packaging/logo.svg", []byte(masterLogoSVG)},
		{"packaging/logo.png", png512},
		{"packaging/cs-burp-router.ico", appICO},
		{"internal/web/static/logo.svg", []byte(masterLogoSVG)},
		{"internal/web/static/favicon.ico", favICO},
	}

	for _, t := range targets {
		if err := os.MkdirAll(filepath.Dir(t.path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(t.path, t.data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func pad4(buf *bytes.Buffer) {
	for buf.Len()%4 != 0 {
		buf.WriteByte(0)
	}
}

func pad8(buf *bytes.Buffer) {
	for buf.Len()%8 != 0 {
		buf.WriteByte(0)
	}
}

func writeUTF16Z(buf *bytes.Buffer, s string) {
	for _, u := range utf16.Encode([]rune(s)) {
		_ = binary.Write(buf, binary.LittleEndian, u)
	}
	_ = binary.Write(buf, binary.LittleEndian, uint16(0))
}

func buildVersionNode(wType uint16, key string, value []byte, valueLenField uint16, children [][]byte) []byte {
	var b bytes.Buffer
	_ = binary.Write(&b, binary.LittleEndian, uint16(0)) // wLength 占位
	_ = binary.Write(&b, binary.LittleEndian, valueLenField)
	_ = binary.Write(&b, binary.LittleEndian, wType)
	writeUTF16Z(&b, key)
	pad4(&b)

	if len(value) > 0 {
		b.Write(value)
	}
	for _, ch := range children {
		pad4(&b)
		b.Write(ch)
	}

	raw := b.Bytes()
	binary.LittleEndian.PutUint16(raw[0:2], uint16(len(raw)))
	return raw
}

func buildStringEntry(key, val string) []byte {
	u16 := append(utf16.Encode([]rune(val)), 0)
	var valBuf bytes.Buffer
	for _, u := range u16 {
		_ = binary.Write(&valBuf, binary.LittleEndian, u)
	}
	// String 节点的 wValueLength 单位为 16-bit WCHAR 字数（含结尾 NUL）
	return buildVersionNode(1, key, valBuf.Bytes(), uint16(len(u16)), nil)
}

func buildVSVersionInfo(verStr string) []byte {
	var v1, v2, v3, v4 uint16 = 1, 0, 0, 0
	_, _ = fmt.Sscanf(verStr, "%d.%d.%d.%d", &v1, &v2, &v3, &v4)
	verMS := (uint32(v1) << 16) | uint32(v2)
	verLS := (uint32(v3) << 16) | uint32(v4)

	var fixed bytes.Buffer
	for _, d := range []uint32{
		0xFEEF04BD, // dwSignature
		0x00010000, // dwStrucVersion
		verMS,      // dwFileVersionMS
		verLS,      // dwFileVersionLS
		verMS,      // dwProductVersionMS
		verLS,      // dwProductVersionLS
		0x0000003F, // dwFileFlagsMask
		0x00000000, // dwFileFlags
		0x00040004, // dwFileOS = VOS_NT_WINDOWS32
		0x00000001, // dwFileType = VFT_APP
		0x00000000, // dwFileSubtype
		0x00000000, // dwFileDateMS
		0x00000000, // dwFileDateLS
	} {
		_ = binary.Write(&fixed, binary.LittleEndian, d)
	}

	kvPairs := [][2]string{
		{"CompanyName", "CS-Burp-Router [Hxy]"},
		{"FileDescription", "CS-Burp-Router Smart Traffic Router for Burp Suite"},
		{"FileVersion", verStr},
		{"InternalName", "cs-burp-router"},
		{"LegalCopyright", "Copyright (c) 2026 CS-Burp-Router [Hxy]"},
		{"OriginalFilename", "cs-burp-router.exe"},
		{"ProductName", "CS-Burp-Router"},
		{"ProductVersion", verStr},
	}
	strEntries := make([][]byte, 0, len(kvPairs))
	for _, kv := range kvPairs {
		strEntries = append(strEntries, buildStringEntry(kv[0], kv[1]))
	}

	langHex := fmt.Sprintf("%04x%04x", langZhCN, codePageUTF16LE)
	strTable := buildVersionNode(1, langHex, nil, 0, strEntries)
	strFileInfo := buildVersionNode(1, "StringFileInfo", nil, 0, [][]byte{strTable})

	var transVal bytes.Buffer
	_ = binary.Write(&transVal, binary.LittleEndian, uint16(langZhCN))
	_ = binary.Write(&transVal, binary.LittleEndian, uint16(codePageUTF16LE))
	varNode := buildVersionNode(0, "Translation", transVal.Bytes(), uint16(transVal.Len()), nil)
	varFileInfo := buildVersionNode(1, "VarFileInfo", nil, 0, [][]byte{varNode})

	return buildVersionNode(
		0,
		"VS_VERSION_INFO",
		fixed.Bytes(),
		uint16(fixed.Len()),
		[][]byte{strFileInfo, varFileInfo},
	)
}

func writeResDirHeader(buf *bytes.Buffer, idEntries uint16) {
	_ = binary.Write(buf, binary.LittleEndian, uint32(0)) // Characteristics
	_ = binary.Write(buf, binary.LittleEndian, uint32(0)) // TimeDateStamp
	_ = binary.Write(buf, binary.LittleEndian, uint16(0)) // MajorVersion
	_ = binary.Write(buf, binary.LittleEndian, uint16(0)) // MinorVersion
	_ = binary.Write(buf, binary.LittleEndian, uint16(0)) // NumberOfNamedEntries
	_ = binary.Write(buf, binary.LittleEndian, idEntries) // NumberOfIdEntries
}

func writeResDirEntry(buf *bytes.Buffer, id uint32, offset uint32, isSubdir bool) {
	if isSubdir {
		offset |= 0x80000000
	}
	_ = binary.Write(buf, binary.LittleEndian, id)
	_ = binary.Write(buf, binary.LittleEndian, offset)
}

type coffResItem struct {
	typeID uint32
	nameID uint32
	langID uint32
	data   []byte
}

func buildCOFFResourceObject(versionBlob, manifestBlob, icoBytes []byte) ([]byte, error) {
	items := make([]coffResItem, 0, 10)

	if len(icoBytes) > 0 {
		frames, grpDir, err := parseICOForPE(icoBytes)
		if err != nil {
			return nil, err
		}
		for i, f := range frames {
			items = append(items, coffResItem{
				typeID: rtIcon,
				nameID: uint32(i + 1),
				langID: langEnUS,
				data:   f.rawPayload,
			})
		}
		items = append(items, coffResItem{
			typeID: rtGroupIcon,
			nameID: 1,
			langID: langEnUS,
			data:   grpDir,
		})
	}

	items = append(items,
		coffResItem{
			typeID: rtVersion,
			nameID: 1,
			langID: langZhCN,
			data:   versionBlob,
		},
		coffResItem{
			typeID: rtManifest,
			nameID: 1,
			langID: langEnUS,
			data:   manifestBlob,
		},
	)

	// PE 规范要求同级目录按 ID 严格升序排列
	slices.SortFunc(items, func(a, b coffResItem) int {
		if a.typeID != b.typeID {
			if a.typeID < b.typeID {
				return -1
			}
			return 1
		}
		if a.nameID != b.nameID {
			if a.nameID < b.nameID {
				return -1
			}
			return 1
		}
		return int(a.langID) - int(b.langID)
	})

	type typeGroup struct {
		typeID  uint32
		indices []int
	}
	var groups []typeGroup
	for idx, it := range items {
		if len(groups) == 0 || groups[len(groups)-1].typeID != it.typeID {
			groups = append(groups, typeGroup{typeID: it.typeID, indices: []int{idx}})
		} else {
			groups[len(groups)-1].indices = append(groups[len(groups)-1].indices, idx)
		}
	}

	// 计算三级资源目录与 DataEntry 偏移量
	l1Size := uint32(16 + len(groups)*8)
	l2Offsets := make([]uint32, len(groups))
	curOff := l1Size
	for i, g := range groups {
		l2Offsets[i] = curOff
		curOff += uint32(16 + len(g.indices)*8)
	}

	l3Offsets := make([]uint32, len(items))
	for i := range items {
		l3Offsets[i] = curOff
		curOff += 24 // 16B header + 1*8B entry
	}

	dataEntryOffsets := make([]uint32, len(items))
	for i := range items {
		dataEntryOffsets[i] = curOff
		curOff += 16 // IMAGE_RESOURCE_DATA_ENTRY
	}

	blobOffsets := make([]uint32, len(items))
	for i, it := range items {
		blobOffsets[i] = curOff
		padded := (uint32(len(it.data)) + 7) &^ 7
		curOff += padded
	}

	var sec bytes.Buffer
	sec.Grow(int(curOff))

	// Level 1: Root (Type IDs)
	writeResDirHeader(&sec, uint16(len(groups)))
	for i, g := range groups {
		writeResDirEntry(&sec, g.typeID, l2Offsets[i], true)
	}

	// Level 2: Name IDs per Type
	for _, g := range groups {
		writeResDirHeader(&sec, uint16(len(g.indices)))
		for _, itemIdx := range g.indices {
			writeResDirEntry(&sec, items[itemIdx].nameID, l3Offsets[itemIdx], true)
		}
	}

	// Level 3: Language ID per Item
	for i, it := range items {
		writeResDirHeader(&sec, 1)
		writeResDirEntry(&sec, it.langID, dataEntryOffsets[i], false)
	}

	// IMAGE_RESOURCE_DATA_ENTRY 列表
	for i, it := range items {
		_ = binary.Write(&sec, binary.LittleEndian, blobOffsets[i])
		_ = binary.Write(&sec, binary.LittleEndian, uint32(len(it.data)))
		_ = binary.Write(&sec, binary.LittleEndian, uint32(0))
		_ = binary.Write(&sec, binary.LittleEndian, uint32(0))
	}

	// 原始资源负载（8 字节对齐）
	for _, it := range items {
		sec.Write(it.data)
		pad8(&sec)
	}

	secBytes := sec.Bytes()
	if uint32(len(secBytes)) != curOff {
		return nil, fmt.Errorf("resource section size mismatch: got %d, want %d", len(secBytes), curOff)
	}

	const (
		coffHeaderSize = 20
		secHeaderSize  = 40
		rawDataOffset  = coffHeaderSize + secHeaderSize
		relocEntrySize = 10
	)
	numRelocs := len(dataEntryOffsets)
	relocOffset := uint32(rawDataOffset + len(secBytes))
	symTableOffset := relocOffset + uint32(numRelocs*relocEntrySize)

	var out bytes.Buffer

	// 1. IMAGE_FILE_HEADER
	_ = binary.Write(&out, binary.LittleEndian, uint16(imageFileMachineAMD64))
	_ = binary.Write(&out, binary.LittleEndian, uint16(1))      // NumberOfSections
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))      // TimeDateStamp
	_ = binary.Write(&out, binary.LittleEndian, symTableOffset) // PointerToSymbolTable
	_ = binary.Write(&out, binary.LittleEndian, uint32(1))      // NumberOfSymbols
	_ = binary.Write(&out, binary.LittleEndian, uint16(0))      // SizeOfOptionalHeader
	_ = binary.Write(&out, binary.LittleEndian, uint16(0))      // Characteristics

	// 2. IMAGE_SECTION_HEADER
	var secName [8]byte
	copy(secName[:], ".rsrc")
	out.Write(secName[:])
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))             // VirtualSize
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))             // VirtualAddress
	_ = binary.Write(&out, binary.LittleEndian, uint32(len(secBytes))) // SizeOfRawData
	_ = binary.Write(&out, binary.LittleEndian, uint32(rawDataOffset)) // PointerToRawData
	_ = binary.Write(&out, binary.LittleEndian, relocOffset)           // PointerToRelocations
	_ = binary.Write(&out, binary.LittleEndian, uint32(0))             // PointerToLinenumbers
	_ = binary.Write(&out, binary.LittleEndian, uint16(numRelocs))     // NumberOfRelocations
	_ = binary.Write(&out, binary.LittleEndian, uint16(0))             // NumberOfLinenumbers
	_ = binary.Write(&out, binary.LittleEndian, uint32(imageScnCntInitializedData|imageScnMemRead))

	// 3. Section Raw Data
	out.Write(secBytes)

	// 4. COFF Relocations (ADDR32NB 指向符号 0 ".rsrc")
	for _, rvaOff := range dataEntryOffsets {
		_ = binary.Write(&out, binary.LittleEndian, rvaOff)
		_ = binary.Write(&out, binary.LittleEndian, uint32(0)) // Symbol index 0
		_ = binary.Write(&out, binary.LittleEndian, uint16(imageRelAMD64Addr32NB))
	}

	// 5. COFF Symbol Table (18 bytes): Symbol 0 = ".rsrc"
	out.Write(secName[:])
	_ = binary.Write(&out, binary.LittleEndian, uint32(0)) // Value
	_ = binary.Write(&out, binary.LittleEndian, int16(1))  // SectionNumber = 1
	_ = binary.Write(&out, binary.LittleEndian, uint16(0)) // Type
	_ = binary.Write(&out, binary.LittleEndian, uint8(imageSymClassStatic))
	_ = binary.Write(&out, binary.LittleEndian, uint8(0)) // NumberOfAuxSymbols

	// 6. COFF String Table (4 bytes = empty)
	_ = binary.Write(&out, binary.LittleEndian, uint32(4))

	return out.Bytes(), nil
}
