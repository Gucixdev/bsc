package main

import (
	"fmt"
	"strings"
)

func drawHexNET(buf *strings.Builder, rows, cols, paneW, sepX, dumpX, dumpW, bpr, paneH int,
	ss *SysState, ui *UI, t *Theme, search []byte) {

	ss.mu.RLock()
	var ifaces []string
	for _, n := range ss.Nets {
		if n.Name != "lo" {
			ifaces = append(ifaces, n.Name)
		}
	}
	ss.mu.RUnlock()

	if ui.HexSel >= len(ifaces) {
		ui.HexSel = max(0, len(ifaces)-1)
	}

	var selIface string
	if len(ifaces) > 0 {
		selIface = ifaces[ui.HexSel]
		ensureNetCap(ss, selIface)
	}

	// check which ifaces are capturing
	ss.NetCapMu.Lock()
	capturing := make(map[string]bool, len(ifaces))
	for _, n := range ifaces {
		capturing[n] = netCapRunning[n]
	}
	ss.NetCapMu.Unlock()

	// ── left pane ──
	ifaceLines := make([]string, len(ifaces))
	for i, name := range ifaces {
		dot := "○"
		if capturing[name] {
			dot = "●"
		}
		ss.NetCapMu.Lock()
		sz := len(ss.HexNetBufs[name])
		ss.NetCapMu.Unlock()
		ifaceLines[i] = fmt.Sprintf("%-8s %6s %s", name, fmtBufSize(sz), dot)
	}
	if ui.HexSel < ui.HexRegScroll {
		ui.HexRegScroll = ui.HexSel
	}
	if ui.HexSel >= ui.HexRegScroll+paneH {
		ui.HexRegScroll = ui.HexSel - paneH + 1
	}
	drawLeftPane(buf, 2, paneH, paneW, ifaceLines, ui.HexSel, ui.HexRegScroll, t)

	// ── info line ──
	buf.WriteString(pos(1, dumpX))
	if selIface == "" {
		buf.WriteString(DIM + ansiCol(t.USB) + " no interfaces" + RESET + CLEOL)
		for r := 2; r < rows-2; r++ {
			buf.WriteString(pos(r, dumpX) + CLEOL)
		}
		return
	}

	ss.NetCapMu.Lock()
	capData := make([]byte, len(ss.HexNetBufs[selIface]))
	copy(capData, ss.HexNetBufs[selIface])
	ss.NetCapMu.Unlock()

	var lockStr, lockCol string
	if ui.NetLock {
		lockStr, lockCol = "●LOCK", ansiCol(t.WARN)
	} else {
		lockStr, lockCol = "○free", ansiCol(t.DISK)
	}
	staticInfo := fmt.Sprintf(" %-8s  captured:%s  offset:0x%08x  l=",
		selIface, fmtBufSize(len(capData)), int64(ui.HexScroll)*int64(bpr))
	buf.WriteString(DIM + ansiCol(t.USB) + staticInfo + RESET)
	buf.WriteString(lockCol + lockStr + RESET + CLEOL)

	// auto-tail: scroll so last full screen of data is visible
	if ui.NetLock && len(capData) > 0 {
		visibleRows := rows - 4
		totalRows := (len(capData) + bpr - 1) / bpr
		tail := totalRows - visibleRows
		if tail < 0 {
			tail = 0
		}
		ui.HexScroll = tail
	}

	// clamp scroll
	off := int64(ui.HexScroll) * int64(bpr)
	if int(off) > len(capData) {
		off = int64(len(capData))
	}

	size := bpr * (rows - 4)
	end := int(off) + size
	if end > len(capData) {
		end = len(capData)
	}
	var data []byte
	if int(off) < len(capData) {
		data = capData[off:end]
	}

	renderHexDump(buf, 2, rows-2, dumpX, dumpW, bpr, data, off, search, t)
}
