package main

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// parseHexSearch — "4d 5a" → []byte{0x4d,0x5a}; invalid tokens ignored
func parseHexSearch(s string) []byte {
	var out []byte
	for _, tok := range strings.Fields(s) {
		b, err := hex.DecodeString(tok)
		if err == nil && len(b) == 1 {
			out = append(out, b[0])
		}
	}
	return out
}

const hexNib = "0123456789abcdef"

// hexLine — renders one hex dump line.
// lineCol = ambient ANSI color (set by caller before writing line).
// Uses run-length color encoding: one escape per color-run boundary, not per byte.
func hexLine(baseAddr int64, off int, chunk []byte, bpr int, search []byte, lineCol string, t *Theme) string {
	var sb strings.Builder
	sb.Grow(bpr*4 + 96)

	fmt.Fprintf(&sb, "%010x  ", baseAddr+int64(off))

	// precompute match positions
	matchAt := [256]bool{}
	if len(search) > 0 && len(search) <= bpr {
		for i := 0; i <= len(chunk)-len(search); i++ {
			ok := true
			for j, b := range search {
				if chunk[i+j] != b {
					ok = false
					break
				}
			}
			if ok {
				for j := range search {
					if i+j < 256 {
						matchAt[i+j] = true
					}
				}
			}
		}
	}

	zeroCol := DIM + ansiCol(t.USB)
	selCol := ansiCol(t.SEL) + BOLD

	// kind: 0=lineCol  1=zeroCol  2=selCol
	kind := func(i int) int {
		if i >= len(chunk) {
			return 0
		}
		if matchAt[i] {
			return 2
		}
		if chunk[i] == 0 {
			return 1
		}
		return 0
	}
	cur := 0
	set := func(want int) {
		if cur == want {
			return
		}
		if cur != 0 {
			sb.WriteString(RESET + lineCol)
		}
		switch want {
		case 1:
			sb.WriteString(zeroCol)
		case 2:
			sb.WriteString(selCol)
		}
		cur = want
	}

	// hex part — nibble lookup, run-length color
	for i := 0; i < bpr; i++ {
		if i > 0 && i%8 == 0 {
			sb.WriteByte(' ')
		}
		if i < len(chunk) {
			set(kind(i))
			b := chunk[i]
			sb.WriteByte(hexNib[b>>4])
			sb.WriteByte(hexNib[b&0xf])
			sb.WriteByte(' ')
		} else {
			sb.WriteString("   ")
		}
	}
	if cur != 0 {
		sb.WriteString(RESET + lineCol)
		cur = 0
	}
	sb.WriteByte(' ')

	// ascii part — same run-length logic
	for i := 0; i < bpr; i++ {
		if i < len(chunk) {
			set(kind(i))
			b := chunk[i]
			if b >= 0x20 && b < 0x7f {
				sb.WriteByte(b)
			} else {
				sb.WriteByte('.')
			}
		} else {
			sb.WriteByte(' ')
		}
	}
	if cur != 0 {
		sb.WriteString(RESET)
	}

	return sb.String()
}

// allZero — true if every byte is 0
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// clampStr — truncate string to n runes (rune-aware, handles multi-byte like ─)
func clampStr(s string, n int) string {
	runes := []rune(s)
	if len(runes) > n {
		return string(runes[:n])
	}
	return s
}

// clampVisual — truncate s to n visible columns, skipping ANSI escape sequences
func clampVisual(s string, n int) string {
	vis := 0
	i := 0
	for i < len(s) {
		if s[i] == '\033' {
			// skip ESC[ ... finalByte
			j := i + 1
			if j < len(s) && s[j] == '[' {
				j++
				for j < len(s) && !((s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z')) {
					j++
				}
				if j < len(s) {
					j++
				}
			}
			i = j
		} else {
			if vis == n {
				return s[:i]
			}
			vis++
			i++
		}
	}
	return s
}

// drawLeftPane — renders left pane lines into buf starting at screenRow.
// Returns number of lines written. paneW = width of left pane (no separator).
func drawLeftPane(buf *strings.Builder, screenRow, paneH, paneW int, lines []string, sel, scroll int, t *Theme) {
	for i := 0; i < paneH; i++ {
		idx := scroll + i
		buf.WriteString(pos(screenRow+i, 0))
		if idx < len(lines) {
			s := clampStr(lines[idx], paneW)
			pad := paneW - len(s)
			if idx == sel {
				buf.WriteString(BOLD + ansiCol(t.SEL))
				buf.WriteString(s)
				buf.WriteString(strings.Repeat(" ", pad))
				buf.WriteString(RESET)
			} else {
				buf.WriteString(s)
				buf.WriteString(CLEOL)
			}
		} else {
			buf.WriteString(CLEOL)
		}
	}
}

// renderHexDump — fills rows [startRow, endRow) in dump pane (at dumpX)
func renderHexDump(buf *strings.Builder, startRow, endRow, dumpX, dumpW, bpr int,
	data []byte, baseAddr int64, search []byte, skipZero bool, t *Theme) {

	dim := DIM + ansiCol(t.USB)
	row := startRow
	zeroRun := 0
	for off := 0; row < endRow; off += bpr {
		if off >= len(data) {
			if zeroRun > 0 {
				buf.WriteString(pos(row, dumpX))
				buf.WriteString(dim + fmt.Sprintf("  ··· %d zero rows", zeroRun) + RESET + CLEOL)
				row++
				zeroRun = 0
			}
			buf.WriteString(pos(row, dumpX) + CLEOL)
			row++
			continue
		}
		end := off + bpr
		if end > len(data) {
			end = len(data)
		}
		chunk := data[off:end]

		if skipZero && allZero(chunk) {
			zeroRun++
			continue
		}
		if zeroRun > 0 && row < endRow {
			buf.WriteString(pos(row, dumpX))
			buf.WriteString(dim + fmt.Sprintf("  ··· %d zero rows", zeroRun) + RESET + CLEOL)
			row++
			zeroRun = 0
		}
		if row >= endRow {
			break
		}
		var lineCol string
		if allZero(chunk) {
			lineCol = dim
		} else {
			lineCol = ansiCol(t.DISK)
		}
		line := hexLine(baseAddr, off, chunk, bpr, search, lineCol, t)
		line = clampVisual(line, dumpW)
		buf.WriteString(pos(row, dumpX))
		buf.WriteString(lineCol + line + RESET + CLEOL)
		row++
	}
	if zeroRun > 0 && row < endRow {
		buf.WriteString(pos(row, dumpX))
		buf.WriteString(dim + fmt.Sprintf("  ··· %d zero rows", zeroRun) + RESET + CLEOL)
		row++
	}
}

// drawHexInfo — fills rows-2 with context info (replaces color legend)
func drawHexInfo(buf *strings.Builder, rows, cols int, ui *UI, ss *SysState, t *Theme) {
	dim := DIM + ansiCol(t.USB)
	var info string

	switch ui.HexSource {
	case HEX_MEM:
		regions := parseMaps(ui.HexPID)
		procName := ""
		ss.mu.RLock()
		for _, p := range ss.Procs {
			if p.PID == ui.HexPID {
				procName = p.Comm
				break
			}
		}
		ss.mu.RUnlock()
		var regDetail string
		if ui.HexRegion < len(regions) {
			r := regions[ui.HexRegion]
			regDetail = fmt.Sprintf("  [%d/%d] %s %s  size:%s",
				ui.HexRegion+1, len(regions), r.Perms, r.Name, fmtRegSize(r.End-r.Start))
		}
		info = fmt.Sprintf(" pid:%-6d %-14s%s", ui.HexPID, procName, regDetail)

	case HEX_DISK:
		ss.mu.RLock()
		var allDisks []DiskStat
		allDisks = append(allDisks, ss.Disks...)
		allDisks = append(allDisks, ss.Removable...)
		ss.mu.RUnlock()
		if ui.HexSel < len(allDisks) {
			d := allDisks[ui.HexSel]
			parts := ""
			for i, p := range d.Parts {
				if i > 0 { parts += "  " }
				parts += p.Mount
				if i >= 3 { break }
			}
			info = fmt.Sprintf(" /dev/%-6s  %s  size:%s  mounts: %s",
				d.Dev, d.Model, fmtRegSize(d.SizeBytes), parts)
		}

	case HEX_NET:
		ss.NetCapMu.Lock()
		var ifaces []string
		ss.mu.RLock()
		for _, n := range ss.Nets {
			if n.Name != "lo" { ifaces = append(ifaces, n.Name) }
		}
		ss.mu.RUnlock()
		var sel string
		if ui.HexSel < len(ifaces) { sel = ifaces[ui.HexSel] }
		sz := len(ss.HexNetBufs[sel])
		ss.NetCapMu.Unlock()
		lock := "free"
		if ui.NetLock { lock = "LOCK" }
		info = fmt.Sprintf(" iface:%-8s  buf:%s  l=%s  bpr:%d  offset:0x%x",
			sel, fmtBufSize(sz), lock, 0, int64(ui.HexScroll))
	}

	if ui.HexSearch != "" {
		info += fmt.Sprintf("  /%s", ui.HexSearch)
	}

	buf.WriteString(pos(rows-2, 0))
	buf.WriteString(dim + clampVisual(info, cols) + RESET + CLEOL)
}

func fmtRegSize(sz int64) string {
	if sz >= 1<<20 {
		return fmt.Sprintf("%dM", sz>>20)
	}
	if sz >= 1<<10 {
		return fmt.Sprintf("%dK", sz>>10)
	}
	return fmt.Sprintf("%dB", sz)
}

func fmtBufSize(sz int) string {
	if sz >= 1<<20 {
		return fmt.Sprintf("%dM", sz>>20)
	}
	if sz >= 1<<10 {
		return fmt.Sprintf("%dK", sz>>10)
	}
	return fmt.Sprintf("%dB", sz)
}

func drawHEX(buf *strings.Builder, rows, cols int, ss *SysState, ui *UI, t *Theme) {
	// ── header ──
	srcName := [4]string{"MEM", "DISK", "NET", "VRAM"}
	hdr := fmt.Sprintf(" HEX  src:%s", srcName[ui.HexSource])
	if ui.HexSearchMode {
		hdr += fmt.Sprintf("  /:%s_", ui.HexSearch)
	}
	hdr = clampStr(hdr+strings.Repeat("─", max(0, cols-len(hdr))), cols)
	buf.WriteString(pos(0, 0))
	buf.WriteString(ansiCol(t.HDR) + BOLD + hdr + RESET + CLEOL)

	if ui.Anon {
		msg := " [ANON] hex dump disabled in anonymous mode"
		for r := 1; r < rows-1; r++ {
			buf.WriteString(pos(r, 0) + CLEOL)
		}
		buf.WriteString(pos(rows/2, (cols-len(msg))/2))
		buf.WriteString(ansiCol(t.WARN) + BOLD + msg + RESET)
		drawStatusBar(buf, rows, cols, ui, ui.Interval, ss, t)
		return
	}

	// ── layout ──
	paneW := cols / 4
	if paneW < 22 {
		paneW = 22
	}
	if paneW > 38 {
		paneW = 38
	}
	sepX := paneW
	dumpX := sepX + 1
	dumpW := cols - dumpX
	if dumpW < 20 {
		dumpW = 20
	}

	// bpr — bytes per row; fits dump pane
	// offset(12) + hex(3*bpr + bpr/8) + space + ascii(bpr) = dumpW
	bpr := (dumpW - 12) / 4
	if bpr < 8 {
		bpr = 8
	}
	bpr = (bpr / 8) * 8

	contentRows := rows - 2 // row 0=hdr, rows-1=statusbar
	paneH := contentRows - 2 // -1 more for hint row (rows-2)

	// ── separator ──
	for r := 1; r < rows-1; r++ {
		buf.WriteString(pos(r, sepX))
		buf.WriteString(DIM + ansiCol(t.USB) + "│" + RESET)
	}

	search := parseHexSearch(ui.HexSearch)

	switch ui.HexSource {
	case HEX_MEM:
		drawHexMEM(buf, rows, cols, paneW, sepX, dumpX, dumpW, bpr, paneH, ss, ui, t, search)
	case HEX_DISK:
		drawHexDISK(buf, rows, cols, paneW, sepX, dumpX, dumpW, bpr, paneH, ss, ui, t, search)
	case HEX_NET:
		drawHexNET(buf, rows, cols, paneW, sepX, dumpX, dumpW, bpr, paneH, ss, ui, t, search)
	case HEX_VRAM:
		drawHexVRAM(buf, rows, cols, paneW, sepX, dumpX, dumpW, bpr, paneH, ss, ui, t, search)
	}

	drawHexInfo(buf, rows, cols, ui, ss, t)
	drawStatusBar(buf, rows, cols, ui, ui.Interval, ss, t)
}
