package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// mapRegion — one entry from /proc/PID/maps
type mapRegion struct {
	Start int64
	End   int64
	Perms string
	Name  string
}

func parseMaps(pid int) []mapRegion {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil
	}
	var out []mapRegion
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		parts := strings.SplitN(fields[0], "-", 2)
		if len(parts) != 2 {
			continue
		}
		start, err1 := strconv.ParseInt(parts[0], 16, 64)
		end, err2 := strconv.ParseInt(parts[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		name := ""
		if len(fields) >= 6 {
			name = fields[5]
		}
		out = append(out, mapRegion{Start: start, End: end, Perms: fields[1], Name: name})
	}
	return out
}

func drawHexMEM(buf *strings.Builder, rows, cols, paneW, sepX, dumpX, dumpW, bpr, paneH int,
	ss *SysState, ui *UI, t *Theme, search []byte) {

	// auto-select first readable PID on first entry
	if ui.HexPID == 0 {
		ss.mu.RLock()
		for _, p := range ss.Procs {
			if r := parseMaps(p.PID); len(r) > 0 {
				ui.HexPID = p.PID
				break
			}
		}
		ss.mu.RUnlock()
	}

	regions := parseMaps(ui.HexPID)

	// clamp region index
	if ui.HexRegion >= len(regions) {
		ui.HexRegion = max(0, len(regions)-1)
	}

	// ── left pane: region list ──
	regionLines := make([]string, len(regions))
	for i, r := range regions {
		sz := r.End - r.Start
		name := r.Name
		if name == "" {
			name = "anon"
		}
		regionLines[i] = fmt.Sprintf("[%d]%x %s %s",
			i, r.Start, r.Perms, fmtRegSize(sz))
		if name != "anon" {
			regionLines[i] += " " + name
		}
	}

	if ui.HexRegion < ui.HexRegScroll {
		ui.HexRegScroll = ui.HexRegion
	}
	if ui.HexRegion >= ui.HexRegScroll+paneH {
		ui.HexRegScroll = ui.HexRegion - paneH + 1
	}
	drawLeftPane(buf, 2, paneH, paneW, regionLines, ui.HexRegion, ui.HexRegScroll, t)

	// ── info line ──
	buf.WriteString(pos(1, dumpX))
	if ui.HexPID == 0 {
		buf.WriteString(DIM + ansiCol(t.USB) + " no process" + RESET + CLEOL)
	} else {
		var regInfo string
		if ui.HexRegion < len(regions) {
			r := regions[ui.HexRegion]
			regInfo = fmt.Sprintf(" pid:%d  region:[%d] 0x%x-0x%x %s %s",
				ui.HexPID, ui.HexRegion, r.Start, r.End, r.Perms, r.Name)
		} else {
			regInfo = fmt.Sprintf(" pid:%d  no regions", ui.HexPID)
		}
		buf.WriteString(DIM + ansiCol(t.USB) + clampStr(regInfo, dumpW) + RESET + CLEOL)
	}

	// ── hex dump ──
	if ui.HexPID == 0 || len(regions) == 0 {
		for r := 2; r < rows-2; r++ {
			buf.WriteString(pos(r, dumpX) + CLEOL)
		}
		return
	}

	reg := regions[ui.HexRegion]
	if !strings.Contains(reg.Perms, "r") {
		buf.WriteString(pos(2, dumpX))
		buf.WriteString(ansiCol(t.WARN) + " region not readable" + RESET + CLEOL)
		for r := 3; r < rows-2; r++ {
			buf.WriteString(pos(r, dumpX) + CLEOL)
		}
		return
	}

	size := bpr * (rows - 4)
	off := int64(ui.HexScroll) * int64(bpr)
	readAt := reg.Start + off

	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", ui.HexPID))
	if err != nil {
		buf.WriteString(pos(2, dumpX))
		buf.WriteString(ansiCol(t.WARN) + " EPERM — need root" + RESET + CLEOL)
		for r := 3; r < rows-2; r++ {
			buf.WriteString(pos(r, dumpX) + CLEOL)
		}
		return
	}
	defer f.Close()

	raw := make([]byte, size)
	n, _ := f.ReadAt(raw, readAt)
	data := raw[:n]

	renderHexDump(buf, 2, rows-2, dumpX, dumpW, bpr, data, readAt, search, ui.HexSkipZero, t)
}
