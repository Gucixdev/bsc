package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// readCtxSwTotal — total context switches from /proc/schedstat (all CPUs)
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

// devPrev — previous vmstat/schedstat snapshot for rate calculations
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
}

func readDevG() devGlobal {
	d := devGlobal{mi: map[string]int64{}}
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
	// schedstat: field [9] = nr_switches per cpu line
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
	return d
}

func drawDEV(buf *strings.Builder, rows, cols int, ss *SysState, ui *UI, t *Theme) {
	buf.WriteString(pos(0, 0))
	buf.WriteString(ansiCol(t.HDR) + BOLD + clampStr(" DEV · MAIN "+strings.Repeat("─", max(0, cols-12)), cols) + RESET + CLEOL)
	row := 1

	d := readDevG()
	mi := d.mi

	// ── MEMORY MAP ───────────────────────────────────────────────────────────
	row = devMemMap(buf, row, cols, mi, t)

	// ── SCHEDULER ────────────────────────────────────────────────────────────
	if row < rows-10 {
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.HDR) + clampStr("─── SCHEDULER "+strings.Repeat("─", max(0, cols-14)), cols) + RESET + CLEOL)
		row++
		swRate := d.nrSwitches - devPrev.nrSwitches
		swapIn := d.swapIn - devPrev.swapIn
		swapOut := d.swapOut - devPrev.swapOut
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.DISK) + clampStr(fmt.Sprintf(
			" ctx_switches:%d/s  swap_in:%d  swap_out:%d", swRate, swapIn, swapOut,
		), cols) + RESET + CLEOL)
		row++
		// ctx switch sparkline
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
		tunables := [][2]string{
			{"/proc/sys/vm/swappiness", "swappiness"},
			{"/proc/sys/vm/dirty_ratio", "dirty_ratio"},
			{"/proc/sys/vm/dirty_background_ratio", "dirty_bg"},
			{"/proc/sys/net/core/somaxconn", "somaxconn"},
			{"/proc/sys/net/ipv4/tcp_max_syn_backlog", "syn_backlog"},
			{"/proc/sys/kernel/pid_max", "pid_max"},
			{"/proc/sys/kernel/random/entropy_avail", "entropy"},
			{"/proc/sys/fs/file-nr", "fd_used/max"},
		}
		var tline []string
		for _, tu := range tunables {
			if row >= rows-4 {
				break
			}
			v := "?"
			if data, err := os.ReadFile(tu[0]); err == nil {
				v = strings.TrimSpace(strings.ReplaceAll(string(data), "\t", "/"))
			}
			tline = append(tline, fmt.Sprintf("%s:%s", tu[1], v))
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
	// always reserve at least 12 rows for trace
	const traceReserve = 12
	if row > rows-traceReserve {
		row = rows - traceReserve
	}
	if row < rows-3 {
		tHdr := "─── THREAD TRACE "
		tHdr = clampStr(tHdr+strings.Repeat("─", max(0, cols-len(tHdr))), cols)
		buf.WriteString(pos(row, 0))
		buf.WriteString(ansiCol(t.HDR) + tHdr + RESET + CLEOL)
		row++

		traceRows := rows - row - 2
		if traceRows < 1 {
			traceRows = 1
		}

		ss.traceMu.Lock()

		// collect TIDs: prefer threads of DetailPID, else top-N by ring size
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
		// sort by ring length desc (most active first)
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

	// update deltas
	devPrev.nrSwitches = d.nrSwitches
	devPrev.pgFault = d.pgFault
	devPrev.swapIn = d.swapIn
	devPrev.swapOut = d.swapOut

	drawStatusBar(buf, rows, cols, ui, ui.Interval, ss, t)
}

// devMemMap — renders the memory map visual bar (4 rows), returns next row
func devMemMap(buf *strings.Builder, row, cols int, mi map[string]int64, t *Theme) int {
	buf.WriteString(pos(row, 0))
	buf.WriteString(ansiCol(t.HDR) + clampStr("─── MEMORY MAP "+strings.Repeat("─", max(0, cols-15)), cols) + RESET + CLEOL)
	row++

	totKB := mi["MemTotal"]
	if totKB == 0 {
		totKB = 1
	}
	type seg struct {
		lbl string
		kb  int64
		c   Color
	}
	segs := []seg{
		{"kern", mi["KernelStack"] + mi["Slab"] + mi["PageTables"], t.WARN},
		{"huge", mi["HugePages_Total"] * 2048, t.GPU},
		{"anon", mi["Active(anon)"] + mi["Inactive(anon)"] + mi["Shmem"], t.RAM},
		{"cach", mi["Buffers"] + mi["Cached"], t.DISK},
		{"swap", mi["SwapTotal"] - mi["SwapFree"], t.ZRAM},
		{"free", mi["MemFree"], t.NET},
	}
	mapW := max(1, cols-2)
	widths := make([]int, len(segs))
	for i, s := range segs {
		n := int(s.kb * int64(mapW) / totKB)
		if n < 0 {
			n = 0
		}
		widths[i] = n
	}

	// bar row — percentage inside each segment
	buf.WriteString(pos(row, 0) + " ")
	for i, s := range segs {
		n := widths[i]
		if n == 0 {
			continue
		}
		pct := fmt.Sprintf("%d%%", int(100*s.kb/totKB))
		if len(pct) > n {
			pct = strings.Repeat(" ", n)
		} else {
			pad := n - len(pct)
			pct = strings.Repeat(" ", pad/2) + pct + strings.Repeat(" ", pad-pad/2)
		}
		buf.WriteString(bgCol(s.c) + ansiCol(Color{0, 0, 0}) + pct + RESET)
	}
	buf.WriteString(CLEOL)
	row++

	// label row
	buf.WriteString(pos(row, 0) + " ")
	for i, s := range segs {
		n := widths[i]
		if n == 0 {
			continue
		}
		lbl := s.lbl
		if len(lbl) > n {
			lbl = lbl[:n]
		} else {
			lbl += strings.Repeat(" ", n-len(lbl))
		}
		buf.WriteString(ansiCol(s.c) + lbl + RESET)
	}
	buf.WriteString(CLEOL)
	row++

	// value row
	buf.WriteString(pos(row, 0) + " ")
	for i, s := range segs {
		n := widths[i]
		if n == 0 {
			continue
		}
		v := fmtKB(s.kb)
		if len(v) > n {
			v = v[:n]
		} else {
			v += strings.Repeat(" ", n-len(v))
		}
		buf.WriteString(DIM + ansiCol(t.USB) + v + RESET)
	}
	buf.WriteString(CLEOL)
	row++

	// stats row
	hpT := mi["HugePages_Total"]
	hpF := mi["HugePages_Free"]
	stats := fmt.Sprintf(" total:%s  dirty:%s  wb:%s  huge:%d/%d",
		fmtKB(mi["MemTotal"]), fmtKB(mi["Dirty"]), fmtKB(mi["Writeback"]), hpT-hpF, hpT)
	buf.WriteString(pos(row, 0))
	buf.WriteString(ansiCol(t.DISK) + clampStr(stats, cols) + RESET + CLEOL)
	row++
	// blank separator
	buf.WriteString(pos(row, 0) + CLEOL)
	row++
	return row
}

// devCPUFlags — renders present flags (normal) + absent want-list (WARN), returns next row
func devCPUFlags(buf *strings.Builder, row, cols, rows int, t *Theme) int {
	var allFlags []string
	if raw, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "flags") {
				if colon := strings.IndexByte(line, ':'); colon >= 0 {
					allFlags = strings.Fields(line[colon+1:])
				}
				break
			}
		}
	}
	present := map[string]bool{}
	for _, f := range allFlags {
		present[f] = true
	}

	// all present flags
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

	// absent from want-list → WARN color
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

// devKernelLog — dmesg last warn/err lines, returns next row
func devKernelLog(buf *strings.Builder, row, cols, rows int, t *Theme, anon bool) int {
	if anon {
		if row < rows-3 {
			buf.WriteString(pos(row, 0))
			buf.WriteString(DIM + ansiCol(t.USB) + "  [ANON]" + RESET + CLEOL)
			row++
		}
		return row
	}
	var kmsgs []string
	out := runCmd(1200*time.Millisecond, "dmesg", "--time-format=reltime", "--level=err,warn", "-n", "warn")
	if out != "" {
		lines := strings.Split(out, "\n")
		if len(lines) > 4 {
			lines = lines[len(lines)-4:]
		}
		kmsgs = lines
	} else {
		// fallback: /dev/kmsg non-blocking read
		if f, err := os.Open("/dev/kmsg"); err == nil {
			buf2 := make([]byte, 8192)
			n, _ := f.Read(buf2)
			f.Close()
			for _, l := range strings.Split(string(buf2[:n]), "\n") {
				p := strings.SplitN(l, ";", 2)
				if len(p) == 2 {
					kmsgs = append(kmsgs, p[1])
				}
			}
			if len(kmsgs) > 4 {
				kmsgs = kmsgs[len(kmsgs)-4:]
			}
		}
	}
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

// devPIDDetails — oom, cgroup, ns, registers, disasm for selected PID, returns next row
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

	// registers from /proc/PID/syscall: NR rdi rsi rdx r10 r8 r9 rsp rip
	scRaw, err := os.ReadFile(fmt.Sprintf("/proc/%d/syscall", pid))
	if err != nil {
		return row
	}
	sc := strings.Fields(string(scRaw))
	if len(sc) == 1 && sc[0] == "running" {
		if row < rows-3 {
			buf.WriteString(pos(row, 0))
			buf.WriteString(DIM + ansiCol(t.USB) + "  [running in userspace — regs visible only during syscall]" + RESET + CLEOL)
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

		// syscall name
		if nr, err := strconv.ParseInt(sc[0], 0, 64); err == nil && row < rows-3 {
			name := syscallName(int(nr))
			buf.WriteString(pos(row, 0))
			buf.WriteString(ansiCol(t.SEL) + clampStr(fmt.Sprintf("  syscall: %s(%d)", name, nr), cols) + RESET + CLEOL)
			row++
		}

		// disasm at rip
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
