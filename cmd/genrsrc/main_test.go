package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildICOAndCOFFResourceWithIcons(t *testing.T) {
	sizes := []int{48, 32, 16, 256}
	icoBytes, err := buildICOBytes(sizes)
	if err != nil {
		t.Fatalf("buildICOBytes failed: %v", err)
	}

	frames, grpDir, err := parseICOForPE(icoBytes)
	if err != nil {
		t.Fatalf("parseICOForPE failed: %v", err)
	}
	if len(frames) != len(sizes) {
		t.Fatalf("frames count = %d, want %d", len(frames), len(sizes))
	}
	// GRPICONDIR: 6B header + 4 * 14B entries = 62B
	if len(grpDir) != 6+len(sizes)*14 {
		t.Fatalf("grpDir len = %d, want %d", len(grpDir), 6+len(sizes)*14)
	}
	// 256x256 帧应为 PNG 签名
	if !bytes.HasPrefix(frames[3].rawPayload, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatalf("256x256 frame should be PNG-encoded")
	}

	verBlob := buildVSVersionInfo("1.0.0.0")
	manBlob := []byte("<assembly/>")
	syso, err := buildCOFFResourceObject(verBlob, manBlob, icoBytes)
	if err != nil {
		t.Fatalf("buildCOFFResourceObject failed: %v", err)
	}

	if binary.LittleEndian.Uint16(syso[0:2]) != imageFileMachineAMD64 {
		t.Fatalf("unexpected COFF machine header")
	}
	// NumberOfRelocations 位于 IMAGE_SECTION_HEADER 偏移 20+32 = 52
	numRelocs := binary.LittleEndian.Uint16(syso[52:54])
	wantRelocs := uint16(len(sizes) + 3) // N RT_ICON + 1 RT_GROUP_ICON + 1 RT_VERSION + 1 RT_MANIFEST
	if numRelocs != wantRelocs {
		t.Fatalf("numRelocs = %d, want %d", numRelocs, wantRelocs)
	}
}
