package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
)

const masterLogoSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="512" height="512" fill="none">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#232329"/>
      <stop offset="100%" stop-color="#0F0F12"/>
    </linearGradient>
  </defs>
  <rect x="2" y="2" width="60" height="60" rx="14" fill="url(#bg)"/>
  <rect x="2.5" y="2.5" width="59" height="59" rx="13.5" stroke="#FFFFFF" stroke-opacity="0.14" stroke-width="1"/>
  <path d="M 27 16.5 A 15.5 15.5 0 1 0 27 47.5" stroke="#FFFFFF" stroke-width="5.2" stroke-linecap="round"/>
  <path d="M 30.5 32 L 39.5 43 L 50.5 43" stroke="#10B981" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M 24 32 L 32.5 32 C 37.5 32, 38.5 21, 44.5 21 L 49.5 21" stroke="#3B82F6" stroke-width="5" stroke-linecap="round"/>
  <circle cx="50.5" cy="21" r="3.8" fill="#3B82F6"/>
  <circle cx="24" cy="32" r="4" fill="#FFFFFF"/>
</svg>
`

type pt2 struct {
	x, y float64
}

func buildBurpPolyline() []pt2 {
	const steps = 64
	pts := make([]pt2, 0, steps+3)
	pts = append(pts, pt2{24.0, 32.0})
	p0 := pt2{32.5, 32.0}
	p1 := pt2{37.5, 32.0}
	p2 := pt2{38.5, 21.0}
	p3 := pt2{44.5, 21.0}
	for i := 0; i <= steps; i++ {
		t := float64(i) / float64(steps)
		u := 1.0 - t
		x := u*u*u*p0.x + 3*u*u*t*p1.x + 3*u*t*t*p2.x + t*t*t*p3.x
		y := u*u*u*p0.y + 3*u*u*t*p1.y + 3*u*t*t*p2.y + t*t*t*p3.y
		pts = append(pts, pt2{x, y})
	}
	pts = append(pts, pt2{49.5, 21.0})
	return pts
}

func distSegmentSq(px, py, ax, ay, bx, by float64) float64 {
	vx := bx - ax
	vy := by - ay
	wx := px - ax
	wy := py - ay
	lenSq := vx*vx + vy*vy
	var t float64
	if lenSq > 0 {
		t = (wx*vx + wy*vy) / lenSq
		if t < 0 {
			t = 0
		} else if t > 1 {
			t = 1
		}
	}
	dx := px - (ax + t*vx)
	dy := py - (ay + t*vy)
	return dx*dx + dy*dy
}

func sdRoundedRect(px, py, halfExt, radius float64) float64 {
	qx := math.Abs(px-32.0) - (halfExt - radius)
	qy := math.Abs(py-32.0) - (halfExt - radius)
	outX := math.Max(qx, 0)
	outY := math.Max(qy, 0)
	outside := math.Hypot(outX, outY)
	inside := math.Min(math.Max(qx, qy), 0)
	return outside + inside - radius
}

func distLeftSemicircle(px, py float64) float64 {
	const cx, cy, r = 27.0, 32.0, 15.5
	if px <= cx {
		return math.Abs(math.Hypot(px-cx, py-cy) - r)
	}
	dTop := math.Hypot(px-cx, py-(cy-r))
	dBot := math.Hypot(px-cx, py-(cy+r))
	return math.Min(dTop, dBot)
}

// renderLogoNRGBA 使用超采样抗锯齿在纯 Go 中精确光栅化方案 D（双轨同构 · 蓝绿语义）矢量图标。
func renderLogoNRGBA(size int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	burpPts := buildBurpPolyline()

	sub := 8
	if size > 256 {
		sub = 4
	}

	// 小尺寸（<=24px）光学微调：略微外扩圆角底板并加粗笔画，确保 16x16 任务栏/列表清晰锐利
	halfExt := 30.0
	margin := 2.0
	halfWC := 2.6
	halfWDir := 2.5
	halfWBurp := 2.5
	rBurpDot := 3.8
	rCoreDot := 4.0
	drawHairline := true

	if size <= 24 {
		halfExt = 31.0
		margin = 1.0
		halfWC = 2.9
		halfWDir = 2.8
		halfWBurp = 2.8
		rBurpDot = 4.1
		rCoreDot = 4.3
		drawHairline = size >= 24
	}

	halfWDirSq := halfWDir * halfWDir
	halfWBurpSq := halfWBurp * halfWBurp
	rBurpDotSq := rBurpDot * rBurpDot
	rCoreDotSq := rCoreDot * rCoreDot
	span := 64.0 - 2.0*margin
	scale := 64.0 / float64(size)
	invSub := 1.0 / float64(sub)
	totalSamples := float64(sub * sub)

	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var sumR, sumG, sumB float64
			var hits int

			for sy := 0; sy < sub; sy++ {
				cy := (float64(py) + (float64(sy)+0.5)*invSub) * scale
				for sx := 0; sx < sub; sx++ {
					cx := (float64(px) + (float64(sx)+0.5)*invSub) * scale

					sd := sdRoundedRect(cx, cy, halfExt, 14.0)
					if sd > 0 {
						continue
					}
					hits++

					t := (cy - margin) / span
					if t < 0 {
						t = 0
					} else if t > 1 {
						t = 1
					}
					r := 35.0*(1.0-t) + 15.0*t
					g := 35.0*(1.0-t) + 15.0*t
					b := 41.0*(1.0-t) + 18.0*t

					if drawHairline && sd >= -1.0 {
						const ha = 0.14
						r = r*(1.0-ha) + 255.0*ha
						g = g*(1.0-ha) + 255.0*ha
						b = b*(1.0-ha) + 255.0*ha
					}

					// Layer 1: 左侧 C 型捕获环 (#FFFFFF)
					if distLeftSemicircle(cx, cy) <= halfWC {
						r, g, b = 255.0, 255.0, 255.0
					}

					// Layer 2: 下方 Direct 直连快线 (#10B981)
					if cx >= 27.0 && cx <= 54.0 && cy >= 28.5 && cy <= 46.5 {
						d1 := distSegmentSq(cx, cy, 30.5, 32.0, 39.5, 43.0)
						d2 := distSegmentSq(cx, cy, 39.5, 43.0, 50.5, 43.0)
						if d1 <= halfWDirSq || d2 <= halfWDirSq {
							r, g, b = 16.0, 185.0, 129.0
						}
					}

					// Layer 3: 上方 Burp 代理隧道支路 (#3B82F6)
					if cx >= 20.5 && cx <= 55.5 && cy >= 16.0 && cy <= 35.5 {
						dxDot := cx - 50.5
						dyDot := cy - 21.0
						hitBurp := (dxDot*dxDot + dyDot*dyDot) <= rBurpDotSq
						if !hitBurp {
							for i := 0; i < len(burpPts)-1; i++ {
								if distSegmentSq(cx, cy, burpPts[i].x, burpPts[i].y, burpPts[i+1].x, burpPts[i+1].y) <= halfWBurpSq {
									hitBurp = true
									break
								}
							}
						}
						if hitBurp {
							r, g, b = 59.0, 130.0, 246.0
						}
					}

					// Layer 4: 核心分流原点 (#FFFFFF)
					dxCore := cx - 24.0
					dyCore := cy - 32.0
					if dxCore*dxCore+dyCore*dyCore <= rCoreDotSq {
						r, g, b = 255.0, 255.0, 255.0
					}

					sumR += r
					sumG += g
					sumB += b
				}
			}

			if hits == 0 {
				continue
			}
			fHits := float64(hits)
			alpha := uint8(math.Round((fHits / totalSamples) * 255.0))
			img.SetNRGBA(px, py, color.NRGBA{
				R: uint8(math.Round(sumR / fHits)),
				G: uint8(math.Round(sumG / fHits)),
				B: uint8(math.Round(sumB / fHits)),
				A: alpha,
			})
		}
	}
	return img
}

func encodePNGBytes(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// encodeIconDIB32 将 NRGBA 图像编码为 Windows ICO 标准 32-bit BGRA 自底向上 DIB（含 1-bit AND 掩码）。
func encodeIconDIB32(img *image.NRGBA) []byte {
	w := img.Bounds().Dx()
	h := img.Bounds().Dy()
	xorBytes := w * h * 4
	andRowBytes := ((w + 31) / 32) * 4
	andBytes := andRowBytes * h

	var buf bytes.Buffer
	buf.Grow(40 + xorBytes + andBytes)

	// BITMAPINFOHEADER (40 bytes)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(40))               // biSize
	_ = binary.Write(&buf, binary.LittleEndian, int32(w))                 // biWidth
	_ = binary.Write(&buf, binary.LittleEndian, int32(h*2))               // biHeight (XOR + AND)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))                // biPlanes
	_ = binary.Write(&buf, binary.LittleEndian, uint16(32))               // biBitCount
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))                // biCompression = BI_RGB
	_ = binary.Write(&buf, binary.LittleEndian, uint32(xorBytes+andBytes)) // biSizeImage
	_ = binary.Write(&buf, binary.LittleEndian, int32(0))                 // biXPelsPerMeter
	_ = binary.Write(&buf, binary.LittleEndian, int32(0))                 // biYPelsPerMeter
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))                // biClrUsed
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0))                // biClrImportant

	// XOR Mask: 32-bit BGRA (自底向上)
	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := img.NRGBAAt(x, y)
			buf.WriteByte(c.B)
			buf.WriteByte(c.G)
			buf.WriteByte(c.R)
			buf.WriteByte(c.A)
		}
	}

	// AND Mask: 1-bit 透明掩码 (自底向上，每行对齐至 4 字节；仅全透明像素置 1)
	andRow := make([]byte, andRowBytes)
	for y := h - 1; y >= 0; y-- {
		clear(andRow)
		for x := 0; x < w; x++ {
			if img.NRGBAAt(x, y).A == 0 {
				andRow[x/8] |= 1 << (7 - uint(x%8))
			}
		}
		buf.Write(andRow)
	}

	return buf.Bytes()
}

// buildICOBytes 生成多尺寸标准 Windows .ico 文件（<256 使用 32-bit DIB 保证全平台兼容，256 使用 PNG）。
func buildICOBytes(sizes []int) ([]byte, error) {
	if len(sizes) == 0 {
		return nil, fmt.Errorf("sizes cannot be empty")
	}

	type frame struct {
		w, h    uint8
		payload []byte
	}
	frames := make([]frame, 0, len(sizes))

	for _, sz := range sizes {
		if sz < 1 || sz > 256 {
			return nil, fmt.Errorf("invalid icon size %d", sz)
		}
		img := renderLogoNRGBA(sz)
		var payload []byte
		var err error
		if sz == 256 {
			payload, err = encodePNGBytes(img)
			if err != nil {
				return nil, err
			}
		} else {
			payload = encodeIconDIB32(img)
		}
		var bw uint8
		if sz < 256 {
			bw = uint8(sz)
		}
		frames = append(frames, frame{w: bw, h: bw, payload: payload})
	}

	var out bytes.Buffer
	// ICONDIR (6 bytes)
	_ = binary.Write(&out, binary.LittleEndian, uint16(0))
	_ = binary.Write(&out, binary.LittleEndian, uint16(1))
	_ = binary.Write(&out, binary.LittleEndian, uint16(len(frames)))

	offset := uint32(6 + len(frames)*16)
	for _, f := range frames {
		out.WriteByte(f.w)
		out.WriteByte(f.h)
		out.WriteByte(0) // bColorCount
		out.WriteByte(0) // bReserved
		_ = binary.Write(&out, binary.LittleEndian, uint16(1))
		_ = binary.Write(&out, binary.LittleEndian, uint16(32))
		_ = binary.Write(&out, binary.LittleEndian, uint32(len(f.payload)))
		_ = binary.Write(&out, binary.LittleEndian, offset)
		offset += uint32(len(f.payload))
	}

	for _, f := range frames {
		out.Write(f.payload)
	}
	return out.Bytes(), nil
}

type parsedIconFrame struct {
	entryHeader [12]byte // ICONDIRENTRY 前 12 字节（直接复用至 GRPICONDIRENTRY）
	rawPayload  []byte
}

func parseICOForPE(icoBytes []byte) ([]parsedIconFrame, []byte, error) {
	if len(icoBytes) < 6 {
		return nil, nil, fmt.Errorf("ico too short (%d bytes)", len(icoBytes))
	}
	reserved := binary.LittleEndian.Uint16(icoBytes[0:2])
	icoType := binary.LittleEndian.Uint16(icoBytes[2:4])
	count := int(binary.LittleEndian.Uint16(icoBytes[4:6]))
	if reserved != 0 || icoType != 1 || count <= 0 {
		return nil, nil, fmt.Errorf("invalid ico header (reserved=%d type=%d count=%d)", reserved, icoType, count)
	}
	if len(icoBytes) < 6+count*16 {
		return nil, nil, fmt.Errorf("ico directory truncated")
	}

	frames := make([]parsedIconFrame, 0, count)
	var grp bytes.Buffer
	_ = binary.Write(&grp, binary.LittleEndian, uint16(0))
	_ = binary.Write(&grp, binary.LittleEndian, uint16(1))
	_ = binary.Write(&grp, binary.LittleEndian, uint16(count))

	for i := 0; i < count; i++ {
		entOff := 6 + i*16
		sizeInRes := binary.LittleEndian.Uint32(icoBytes[entOff+8 : entOff+12])
		imgOff := binary.LittleEndian.Uint32(icoBytes[entOff+12 : entOff+16])
		endOff := uint64(imgOff) + uint64(sizeInRes)
		if sizeInRes == 0 || endOff > uint64(len(icoBytes)) {
			return nil, nil, fmt.Errorf("ico entry %d out of bounds (off=%d size=%d)", i, imgOff, sizeInRes)
		}

		var hdr [12]byte
		copy(hdr[:], icoBytes[entOff:entOff+12])
		payload := make([]byte, sizeInRes)
		copy(payload, icoBytes[imgOff:endOff])

		iconID := uint16(i + 1)
		grp.Write(hdr[:])
		_ = binary.Write(&grp, binary.LittleEndian, iconID)

		frames = append(frames, parsedIconFrame{
			entryHeader: hdr,
			rawPayload:  payload,
		})
	}

	return frames, grp.Bytes(), nil
}
