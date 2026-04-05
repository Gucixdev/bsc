package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func readCtxSwTotal() int64 {
	raw, err := os.ReadFile("/proc/schedstat")
	if err != nil {
		return 0
	}
	var total int64
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "cpu") || strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) > 9 {
			n, _ := strconv.ParseInt(f[9], 10, 64)
			total += n
		}
	}
	return total
}

// cpuFlagsCache — read once; CPU flags never change at runtime
var cpuFlagsCache []string

func getCPUFlags() []string {
	if cpuFlagsCache != nil {
		return cpuFlagsCache
	}
	if raw, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "flags") {
				if colon := strings.IndexByte(line, ':'); colon >= 0 {
					cpuFlagsCache = strings.Fields(line[colon+1:])
				}
				break
			}
		}
	}
	if cpuFlagsCache == nil {
		cpuFlagsCache = []string{}
	}
	return cpuFlagsCache
}

// devPrev holds previous vmstat/schedstat snapshot for rate calculations
var devPrev struct {
	nrSwitches int64
	pgFault    int64
	swapIn     int64
	swapOut    int64
}

type devGlobal struct {
	mi         map[string]int64
	nrSwitches int64
	pgFault    int64
	swapIn     int64
	swapOut    int64
	swRate     int64 // ctx switches/s delta
	swapInD    int64 // swap_in delta
	swapOutD   int64 // swap_out delta
	tunables   map[string]string // kernel tunable values keyed by label
}

func readDevG() devGlobal {
	d := devGlobal{mi: map[string]int64{}, tunables: map[string]string{}}
	if raw, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			p := strings.SplitN(line, ":", 2)
			if len(p) != 2 {
				continue
			}
			f := strings.Fields(p[1])
			if len(f) == 0 {
				continue
			}
			n, _ := strconv.ParseInt(f[0], 10, 64)
			d.mi[strings.TrimSpace(p[0])] = n
		}
	}
	if raw, err := os.ReadFile("/proc/vmstat"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			n, _ := strconv.ParseInt(f[1], 10, 64)
			switch f[0] {
			case "pgfault":
				d.pgFault = n
			case "pswpin":
				d.swapIn = n
			case "pswpout":
				d.swapOut = n
			}
		}
	}
	if raw, err := os.ReadFile("/proc/schedstat"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "cpu") || strings.HasPrefix(line, "cpu ") {
				continue
			}
			f := strings.Fields(line)
			if len(f) > 9 {
				n, _ := strconv.ParseInt(f[9], 10, 64)
				d.nrSwitches += n
			}
		}
	}
	d.swRate  = d.nrSwitches - devPrev.nrSwitches
	d.swapInD  = d.swapIn - devPrev.swapIn
	d.swapOutD = d.swapOut - devPrev.swapOut
	devPrev.nrSwitches = d.nrSwitches
	devPrev.pgFault    = d.pgFault
	devPrev.swapIn     = d.swapIn
	devPrev.swapOut    = d.swapOut

	for _, tu := range [][2]string{
		{"/proc/sys/vm/swappiness", "swappiness"},
		{"/proc/sys/vm/dirty_ratio", "dirty_ratio"},
		{"/proc/sys/vm/dirty_background_ratio", "dirty_bg"},
		{"/proc/sys/net/core/somaxconn", "somaxconn"},
		{"/proc/sys/net/ipv4/tcp_max_syn_backlog", "syn_backlog"},
		{"/proc/sys/kernel/pid_max", "pid_max"},
		{"/proc/sys/kernel/random/entropy_avail", "entropy"},
		{"/proc/sys/fs/file-nr", "fd_used/max"},
	} {
		v := "?"
		if data, err := os.ReadFile(tu[0]); err == nil {
			v = strings.TrimSpace(strings.ReplaceAll(string(data), "\t", "/"))
		}
		d.tunables[tu[1]] = v
	}
	return d
}

// buildBoxedRows converts a flat ColLine list (Bold+Title = section boundary)
// into pre-rendered rows with purple box borders.
// Each section: ╭─ title ──╮ / │ content │ / ╰──────────╯ / blank gap.
// Every returned string has exactly colW visible characters.
func buildBoxedRows(lines []ColLine, colW int, t *Theme) []string {
	if colW < 6 {
		colW = 6
	}
	innerW := colW - 2 // space between │ borders

	type section struct {
		title string
		body  []ColLine
	}
	var secs []section
	var cur *section
	for _, l := range lines {
		if l.Bold {
			if cur != nil {
				secs = append(secs, *cur)
			}
			cur = &section{title: l.Title}
		} else if cur != nil {
			cur.body = append(cur.body, l)
		}
	}
	if cur != nil {
		secs = append(secs, *cur)
	}

	border := ansiCol(t.HDR)
	pad := func(s string, w int) string {
		v := visLen(s)
		if v >= w {
			return clampVisual(s, w)
		}
		return s + strings.Repeat(" ", w-v)
	}

	var out []string
	for _, sec := range secs {
		title := sec.title
		dashes := max(0, innerW-len(title)-3)
		if title != "" {
			out = append(out, border+"╭─ "+title+" "+strings.Repeat("─", dashes)+"╮"+RESET)
		} else {
			out = append(out, border+"╭"+strings.Repeat("─", innerW)+"╮"+RESET)
		}
		for _, cl := range sec.body {
			var text string
			if cl.Pre {
				text = clampVisual(cl.Text, innerW)
			} else {
				attr := ansiCol(cl.C)
				if cl.Dim {
					attr = DIM + attr
				}
				text = attr + clampStr(cl.Text, innerW) + RESET
			}
			out = append(out, border+"│"+RESET+pad(text, innerW)+border+"│"+RESET)
		}
		out = append(out, border+"╰"+strings.Repeat("─", innerW)+"╯"+RESET)
		out = append(out, "")
	}
	return out
}

// devCPUFlags — renders present flags (normal) + absent want-list (WARN), returns next row
func devCPUFlags(buf *strings.Builder, row, cols, rows int, t *Theme) int {
	allFlags := getCPUFlags()
	present := map[string]bool{}
	for _, f := range allFlags {
		present[f] = true
	}

	lb := ""
	for _, f := range allFlags {
		if row >= rows-3 {
			break
		}
		if lb != "" && len(lb)+1+len(f) > cols-1 {
			buf.WriteString(pos(row, 0))
			buf.WriteString(ansiCol(t.DISK) + lb + RESET + CLEOL)
			row++
			lb = f
		} else {
			if lb == "" {
				lb = f
			} else {
				lb += " " + f
			}
		}
	}
	if lb != "" && row < rows-3 {
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.DISK) + lb + RESET + CLEOL)
		row++
	}

	// absent from want-list → WARN
	want := []string{
		"fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic",
		"sep", "mtrr", "pge", "mca", "cmov", "pat", "pse36", "clflush", "mmx",
		"fxsr", "sse", "sse2", "ss", "ht", "syscall", "nx", "lm", "nopl",
		"pni", "ssse3", "cx16", "sse4_1", "sse4_2", "popcnt",
		"avx", "avx2", "avx512f", "avx512dq", "avx512bw", "avx512vl",
		"f16c", "fma",
		"aes", "pclmulqdq", "sha_ni", "rdrand", "rdseed", "smep", "smap",
		"vmx", "svm", "bmi1", "bmi2", "adx", "lzcnt",
		"ibrs", "ibpb", "stibp", "ssbd",
	}
	lb = ""
	for _, f := range want {
		if present[f] {
			continue
		}
		if row >= rows-3 {
			break
		}
		if lb != "" && len(lb)+1+len(f) > cols-1 {
			buf.WriteString(pos(row, 0))
			buf.WriteString(ansiCol(t.WARN) + lb + RESET + CLEOL)
			row++
			lb = f
		} else {
			if lb == "" {
				lb = f
			} else {
				lb += " " + f
			}
		}
	}
	if lb != "" && row < rows-3 {
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.WARN) + lb + RESET + CLEOL)
		row++
	}
	return row
}

func fetchKernelLog() []string {
	out := runCmd(1200*time.Millisecond, "dmesg", "--time-format=reltime", "--level=err,warn", "-n", "warn")
	if out != "" {
		lines := strings.Split(out, "\n")
		if len(lines) > 4 {
			lines = lines[len(lines)-4:]
		}
		return lines
	}
	var kmsgs []string
	if f, err := os.Open("/dev/kmsg"); err == nil {
		b := make([]byte, 8192)
		n, _ := f.Read(b)
		f.Close()
		for _, l := range strings.Split(string(b[:n]), "\n") {
			p := strings.SplitN(l, ";", 2)
			if len(p) == 2 {
				kmsgs = append(kmsgs, p[1])
			}
		}
		if len(kmsgs) > 4 {
			kmsgs = kmsgs[len(kmsgs)-4:]
		}
	}
	return kmsgs
}

// devKernelLog — dmesg last warn/err lines (cached 5s), returns next row
func devKernelLog(buf *strings.Builder, row, cols, rows int, t *Theme, anon bool) int {
	if anon {
		if row < rows-3 {
			buf.WriteString(pos(row, 0))
			buf.WriteString(DIM + ansiCol(t.USB) + "  [ANON]" + RESET + CLEOL)
			row++
		}
		return row
	}
	kmsgs, _ := bgKernelLog.get(fetchKernelLog)
	if len(kmsgs) == 0 {
		if row < rows-3 {
			buf.WriteString(pos(row, 0))
			buf.WriteString(DIM + ansiCol(t.USB) + "  (no recent warnings)" + RESET + CLEOL)
			row++
		}
	} else {
		for _, l := range kmsgs {
			if row >= rows-3 {
				break
			}
			buf.WriteString(pos(row, 0))
			buf.WriteString(DIM + ansiCol(t.WARN) + clampStr("  "+strings.TrimSpace(l), cols) + RESET + CLEOL)
			row++
		}
	}
	return row
}

// devPIDDetails — oom, cgroup, ns, registers for selected PID, returns next row
func devPIDDetails(buf *strings.Builder, row, cols, rows, pid int, t *Theme, anon bool) int {
	buf.WriteString(pos(row, 0))
	buf.WriteString(ansiCol(t.HDR) + clampStr(fmt.Sprintf("─── PID %d DETAILS ", pid)+
		strings.Repeat("─", max(0, cols-20)), cols) + RESET + CLEOL)
	row++

	oom, _ := os.ReadFile(fmt.Sprintf("/proc/%d/oom_score", pid))
	oomAdj, _ := os.ReadFile(fmt.Sprintf("/proc/%d/oom_score_adj", pid))
	cgRaw, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	cg := ""
	if parts := strings.SplitN(strings.TrimSpace(string(cgRaw)), ":", 3); len(parts) == 3 {
		cg = parts[2]
	}
	nsEntries, _ := os.ReadDir(fmt.Sprintf("/proc/%d/ns", pid))
	var nsNames []string
	for _, e := range nsEntries {
		nsNames = append(nsNames, e.Name())
	}
	if row < rows-3 {
		cgDisplay := cg
		if anon && cgDisplay != "" {
			cgDisplay = "[***]"
		}
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.DISK) + clampStr(fmt.Sprintf(
			"  oom:%s adj:%s  cg:%s",
			strings.TrimSpace(string(oom)), strings.TrimSpace(string(oomAdj)), cgDisplay,
		), cols) + RESET + CLEOL)
		row++
	}
	if row < rows-3 && len(nsNames) > 0 {
		buf.WriteString(pos(row, 0))
		buf.WriteString(DIM + ansiCol(t.DISK) + clampStr("  ns: "+strings.Join(nsNames, " "), cols) + RESET + CLEOL)
		row++
	}

	scRaw, err := os.ReadFile(fmt.Sprintf("/proc/%d/syscall", pid))
	if err != nil {
		return row
	}
	sc := strings.Fields(string(scRaw))
	if len(sc) == 1 && sc[0] == "running" {
		if row < rows-3 {
			buf.WriteString(pos(row, 0))
			buf.WriteString(DIM + ansiCol(t.USB) + "  [running in userspace]" + RESET + CLEOL)
			row++
		}
		return row
	}
	if len(sc) != 9 {
		return row
	}

	if !anon {
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.HDR) + clampStr("─── REGISTERS & DISASM "+strings.Repeat("─", max(0, cols-23)), cols) + RESET + CLEOL)
		row++

		names := []string{"rax", "rdi", "rsi", "rdx", "r10", "r8 ", "r9 ", "rsp", "rip"}
		perLine := max(1, cols/30)
		for i := 0; i < 9 && row < rows-3; i += perLine {
			var pairs []string
			for j := 0; j < perLine && i+j < 9; j++ {
				pairs = append(pairs, fmt.Sprintf("%s:%s", names[i+j], sc[i+j]))
			}
			buf.WriteString(pos(row, 0))
			buf.WriteString(ansiCol(t.DISK) + clampStr("  "+strings.Join(pairs, "  "), cols) + RESET + CLEOL)
			row++
		}

		if nr, err := strconv.ParseInt(sc[0], 0, 64); err == nil && row < rows-3 {
			name := syscallName(int(nr))
			buf.WriteString(pos(row, 0))
			buf.WriteString(ansiCol(t.SEL) + clampStr(fmt.Sprintf("  syscall: %s(%d)", name, nr), cols) + RESET + CLEOL)
			row++
		}

		if row < rows-5 {
			buf.WriteString(pos(row, 0))
			buf.WriteString(DIM + ansiCol(t.USB) + clampStr(fmt.Sprintf("  disasm @ rip %s:", sc[8]), cols) + RESET + CLEOL)
			row++
			for _, dline := range disasmAtRIP(pid, sc[8], rows-row-3) {
				if row >= rows-3 {
					break
				}
				buf.WriteString(pos(row, 0))
				buf.WriteString(ansiCol(t.DISK) + clampStr(dline, cols) + RESET + CLEOL)
				row++
			}
		}
	}
	return row
}

// drawDEVMain — page 0: scheduler/tunables/CPU flags/IRQs/kernel log/PID details/thread trace
func drawDEVMain(buf *strings.Builder, rows, cols int, ss *SysState, ui *UI, t *Theme) {
	d, _ := bgDevG.get(readDevG)
	row := 1

	// ── SCHEDULER ────────────────────────────────────────────────────────────
	if row < rows-10 {
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.HDR) + clampStr("─── SCHEDULER "+strings.Repeat("─", max(0, cols-14)), cols) + RESET + CLEOL)
		row++
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.DISK) + clampStr(fmt.Sprintf(
			" ctx_switches:%d/s  swap_in:%d  swap_out:%d", d.swRate, d.swapInD, d.swapOutD,
		), cols) + RESET + CLEOL)
		row++
		ss.mu.RLock()
		ctxHist := append([]float64(nil), ss.HistCtxSw...)
		ss.mu.RUnlock()
		if len(ctxHist) > 0 && row < rows-3 {
			buf.WriteString(pos(row, 0))
			buf.WriteString(DIM + ansiCol(t.DISK) + " " + sparkline(ctxHist) + RESET + CLEOL)
			row++
		}
	}

	// ── KERNEL TUNABLES ───────────────────────────────────────────────────────
	if row < rows-8 {
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.HDR) + clampStr("─── KERNEL TUNABLES "+strings.Repeat("─", max(0, cols-20)), cols) + RESET + CLEOL)
		row++
		keys := []string{"swappiness", "dirty_ratio", "dirty_bg", "somaxconn", "syn_backlog", "pid_max", "entropy", "fd_used/max"}
		var tline []string
		for _, k := range keys {
			if row >= rows-4 {
				break
			}
			tline = append(tline, fmt.Sprintf("%s:%s", k, d.tunables[k]))
			if len(tline) == 4 {
				buf.WriteString(pos(row, 0))
				buf.WriteString(ansiCol(t.DISK) + clampStr("  "+strings.Join(tline, "  "), cols) + RESET + CLEOL)
				row++
				tline = tline[:0]
			}
		}
		if len(tline) > 0 && row < rows-4 {
			buf.WriteString(pos(row, 0))
			buf.WriteString(ansiCol(t.DISK) + clampStr("  "+strings.Join(tline, "  "), cols) + RESET + CLEOL)
			row++
		}
	}

	// ── CPU FLAGS ─────────────────────────────────────────────────────────────
	if row < rows-5 {
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.HDR) + clampStr("─── CPU FLAGS "+strings.Repeat("─", max(0, cols-14)), cols) + RESET + CLEOL)
		row++
		row = devCPUFlags(buf, row, cols, rows, t)
	}

	// ── TOP IRQs ──────────────────────────────────────────────────────────────
	if row < rows-6 {
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.HDR) + BOLD + clampStr("─── TOP IRQs "+strings.Repeat("─", max(0, cols-13)), cols) + RESET + CLEOL)
		row++
		ss.mu.RLock()
		irqs := ss.IRQs
		ss.mu.RUnlock()
		for i := 0; i < 4 && i < len(irqs) && row < rows-4; i++ {
			irq := irqs[i]
			c := t.DISK
			if irq.Delta > 50000 {
				c = t.WARN
			}
			buf.WriteString(pos(row, 0))
			buf.WriteString(ansiCol(c) + clampStr(fmt.Sprintf(
				"  %-28s  Δ%-8d  total:%d", irq.Name, irq.Delta, irq.Count,
			), cols) + RESET + CLEOL)
			row++
		}
	}

	// ── KERNEL LOG ────────────────────────────────────────────────────────────
	if row < rows-5 {
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.HDR) + clampStr("─── KERNEL LOG "+strings.Repeat("─", max(0, cols-15)), cols) + RESET + CLEOL)
		row++
		row = devKernelLog(buf, row, cols, rows, t, ui.Anon)
	}

	// ── PID DETAILS ───────────────────────────────────────────────────────────
	if ui.DetailPID > 0 && row < rows-5 {
		row = devPIDDetails(buf, row, cols, rows, ui.DetailPID, t, ui.Anon)
	}

	// ── THREAD SYSCALL TRACE ──────────────────────────────────────────────────
	const traceReserve = 12
	if row > rows-traceReserve {
		row = rows - traceReserve
	}
	if row < rows-3 {
		tHdr := "─── THREAD TRACE "
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.HDR) + clampStr(tHdr+strings.Repeat("─", max(0, cols-len(tHdr))), cols) + RESET + CLEOL)
		row++

		traceRows := rows - row - 2
		if traceRows < 1 {
			traceRows = 1
		}

		ss.traceMu.Lock()
		type tidEntry struct {
			tid  int
			comm string
			ring []TraceEntry
		}
		var entries []tidEntry
		filterPID := ui.DetailPID
		for tid, ring := range ss.threadRings {
			if filterPID != 0 && ss.threadPIDs[tid] != filterPID {
				continue
			}
			entries = append(entries, tidEntry{tid, ss.threadComms[tid], append([]TraceEntry(nil), ring...)})
		}
		for i := 1; i < len(entries); i++ {
			for j := i; j > 0 && len(entries[j].ring) > len(entries[j-1].ring); j-- {
				entries[j], entries[j-1] = entries[j-1], entries[j]
			}
		}
		ss.traceMu.Unlock()

		ncols := max(1, min(len(entries), cols/24))
		if ncols > 6 {
			ncols = 6
		}
		ui.TraceNCols = ncols
		tidStart := min(ui.CoreOffset, max(0, len(entries)-ncols))
		ui.CoreOffset = tidStart
		colW := cols / ncols

		var traceCols [][]ColLine
		var traceWidths []int
		for ci := 0; ci < ncols; ci++ {
			idx := tidStart + ci
			var ring []TraceEntry
			var hdr string
			if idx < len(entries) {
				e := entries[idx]
				ring = e.ring
				hdr = fmt.Sprintf(" %d:%s", e.tid, e.comm)
			} else {
				hdr = " -"
			}
			total := len(ring)
			lines := []ColLine{{Text: hdr, C: t.CPU, Bold: true}}
			for ri := 0; ri < traceRows-1; ri++ {
				ridx := total - 1 - (ui.DevScroll + ri)
				if ridx < 0 {
					break
				}
				e := ring[ridx]
				text := e.Syscall
				if e.Count > 1 {
					text = fmt.Sprintf("%s×%d", e.Syscall, e.Count)
				}
				lines = append(lines, ColLine{Text: text, C: t.DISK})
			}
			traceCols = append(traceCols, lines)
			w := colW
			if ci == ncols-1 {
				w = cols - colW*(ncols-1)
			}
			traceWidths = append(traceWidths, w)
		}
		renderCols(buf, row, traceRows, traceCols, traceWidths, t)
		row += traceRows
	}

	for ; row < rows-2; row++ {
		buf.WriteString(pos(row, 0) + CLEOL)
	}
	drawHints(buf, rows-2, cols, ui, t)
}

// drawDEVSecOpt — page 1: SEC (left) + OPT (right) with purple box borders
func drawDEVSecOpt(buf *strings.Builder, rows, cols int, ss *SysState, ui *UI, t *Theme) {
	divX := cols / 2
	leftW := max(10, divX-1)
	rightW := max(10, cols-divX-1)

	for r := 1; r < rows-1; r++ {
		buf.WriteString(pos(r, divX))
		buf.WriteString(ansiCol(t.HDR) + "│" + RESET)
	}

	secLines, _ := bgSEC.get(func() []ColLine { return buildSecLines(ss, ui, t) })
	optLines, _ := bgOPT.get(collectOPT)

	secRows := buildBoxedRows(secLines, leftW, t)
	optRows := buildBoxedRows(optLines, rightW, t)

	displayRows := rows - 2
	maxH := max(len(secRows), len(optRows))
	maxScroll := max(0, maxH-displayRows)
	if ui.SecScroll > maxScroll {
		ui.SecScroll = maxScroll
	}

	for r := 0; r < displayRows; r++ {
		si := ui.SecScroll + r
		buf.WriteString(pos(r+1, 0))
		if si < len(secRows) {
			vl := visLen(secRows[si])
			buf.WriteString(secRows[si] + strings.Repeat(" ", max(0, leftW-vl)))
		} else {
			buf.WriteString(strings.Repeat(" ", leftW))
		}
		buf.WriteString(pos(r+1, divX+1))
		if si < len(optRows) {
			buf.WriteString(optRows[si])
		}
		buf.WriteString(CLEOL)
	}

	pct := 0
	if maxH > 0 {
		pct = (ui.SecScroll + displayRows/2) * 100 / maxH
	}
	fmt.Fprintf(buf, "%s%s %d%%%s%s", pos(rows-2, 0), DIM+ansiCol(t.USB), pct, RESET, CLEOL)
}

func drawDEV(buf *strings.Builder, rows, cols int, ss *SysState, ui *UI, t *Theme) {
	srcName := [2]string{"MAIN", "SEC/OPT"}[ui.DevView]
	buf.WriteString(pos(0, 0))
	buf.WriteString(ansiCol(t.HDR) + BOLD + clampStr(" DEV·"+srcName+" "+strings.Repeat("─", max(0, cols-10)), cols) + RESET + CLEOL)
	// clear content area to avoid stale chars from previous page/tab
	for r := 1; r < rows-1; r++ {
		buf.WriteString(pos(r, 0) + CLEOL)
	}

	if ui.DevView == 0 {
		drawDEVMain(buf, rows, cols, ss, ui, t)
	} else {
		drawDEVSecOpt(buf, rows, cols, ss, ui, t)
	}

	drawStatusBar(buf, rows, cols, ui, ui.Interval, ss, t)
}
