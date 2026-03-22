package main

import (
	"fmt"
	"os"
	"strings"
)

// hexReadDisk — pread /dev/DEV at byte offset
func hexReadDisk(dev string, off int64, size int) ([]byte, int64) {
	if dev == "" {
		return nil, 0
	}
	f, err := os.Open("/dev/" + dev)
	if err != nil {
		return nil, 0
	}
	defer f.Close()
	out := make([]byte, size)
	n, _ := f.ReadAt(out, off)
	return out[:n], off
}

func drawHexDISK(buf *strings.Builder, rows, cols, paneW, sepX, dumpX, dumpW, bpr, paneH int,
	ss *SysState, ui *UI, t *Theme, search []byte) {

	ss.mu.RLock()
	var allDisks []DiskStat
	allDisks = append(allDisks, ss.Disks...)
	allDisks = append(allDisks, ss.Removable...)
	ss.mu.RUnlock()

	if ui.HexSel >= len(allDisks) {
		ui.HexSel = max(0, len(allDisks)-1)
	}

	// ── left pane ──
	diskLines := make([]string, len(allDisks))
	for i, d := range allDisks {
		kind := "SSD"
		if d.Rotary {
			kind = "HDD"
		}
		if d.Optical {
			kind = "OPT"
		}
		diskLines[i] = fmt.Sprintf("/dev/%-6s %s", d.Dev, kind)
	}
	if ui.HexSel < ui.HexRegScroll {
		ui.HexRegScroll = ui.HexSel
	}
	if ui.HexSel >= ui.HexRegScroll+paneH {
		ui.HexRegScroll = ui.HexSel - paneH + 1
	}
	drawLeftPane(buf, 2, paneH, paneW, diskLines, ui.HexSel, ui.HexRegScroll, t)

	// ── info line ──
	buf.WriteString(pos(1, dumpX))
	if len(allDisks) == 0 {
		buf.WriteString(DIM + ansiCol(t.USB) + " no disks" + RESET + CLEOL)
		for r := 2; r < rows-2; r++ {
			buf.WriteString(pos(r, dumpX) + CLEOL)
		}
		return
	}
	dev := allDisks[ui.HexSel].Dev
	off := int64(ui.HexScroll) * int64(bpr)
	info := fmt.Sprintf(" /dev/%-8s  offset:0x%010x", dev, off)
	buf.WriteString(DIM + ansiCol(t.USB) + clampStr(info, dumpW) + RESET + CLEOL)

	// ── hex dump ──
	size := bpr * (rows - 4)
	data, baseOff := hexReadDisk(dev, off, size)
	if data == nil {
		buf.WriteString(pos(2, dumpX))
		buf.WriteString(ansiCol(t.WARN) + " cannot open /dev/" + dev + RESET + CLEOL)
		for r := 3; r < rows-2; r++ {
			buf.WriteString(pos(r, dumpX) + CLEOL)
		}
		return
	}
	renderHexDump(buf, 2, rows-2, dumpX, dumpW, bpr, data, baseOff, search, t)
}
