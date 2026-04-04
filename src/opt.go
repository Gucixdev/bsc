package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func readSysctlOpt(key string) string {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	raw, err := os.ReadFile(path)
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(raw))
}

func governorSummary() (string, bool) {
	entries, _ := os.ReadDir("/sys/devices/system/cpu")
	counts := map[string]int{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "cpu") || len(name) < 4 || name[3] < '0' || name[3] > '9' {
			continue
		}
		raw, err := os.ReadFile("/sys/devices/system/cpu/" + name + "/cpufreq/scaling_governor")
		if err != nil {
			continue
		}
		counts[strings.TrimSpace(string(raw))]++
	}
	if len(counts) == 0 {
		return "n/a", false
	}
	var parts []string
	for gov, n := range counts {
		parts = append(parts, fmt.Sprintf("%s×%d", gov, n))
	}
	gov := parts[0]
	good := strings.Contains(gov, "performance") || strings.Contains(gov, "schedutil")
	return strings.Join(parts, " "), good
}

func ioSchedulers() []string {
	entries, _ := os.ReadDir("/sys/block")
	var out []string
	for _, e := range entries {
		raw, err := os.ReadFile("/sys/block/" + e.Name() + "/queue/scheduler")
		if err != nil {
			continue
		}
		sched := strings.TrimSpace(string(raw))
		if i := strings.Index(sched, "["); i >= 0 {
			if j := strings.Index(sched, "]"); j > i {
				sched = sched[i+1 : j]
			}
		}
		out = append(out, e.Name()+":"+sched)
	}
	return out
}

func readAheadKB(dev string) int {
	raw, err := os.ReadFile("/sys/block/" + dev + "/queue/read_ahead_kb")
	if err != nil {
		return -1
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	return n
}

func checkTHP() string {
	raw, err := os.ReadFile("/sys/kernel/mm/transparent_hugepage/enabled")
	if err != nil {
		return "n/a"
	}
	s := strings.TrimSpace(string(raw))
	if i := strings.Index(s, "["); i >= 0 {
		if j := strings.Index(s, "]"); j > i {
			return s[i+1 : j]
		}
	}
	return s
}

func collectOPT() []ColLine {
	var lines []ColLine

	addh := func(name string) {
		lines = append(lines, ColLine{Text: " " + BOLD + name, Pre: false, Bold: true})
	}
	addl := func(label, val string, c Color) {
		text := fmt.Sprintf("  %s%-24s%s%s%s", DIM, label, RESET, ansiCol(c), val)
		lines = append(lines, ColLine{Text: text, Pre: true})
	}
	addn := func(label string) {
		text := fmt.Sprintf("  %s%-24s%s%s%s", DIM, label, RESET, DIM, "n/a")
		lines = append(lines, ColLine{Text: text, Pre: true, Dim: true})
	}

	bc := func(good bool, t ...Color) Color {
		if good {
			return Color{0, 255, 65}
		}
		return Color{255, 0, 0}
	}
	_ = bc

	ok   := Color{0, 255, 65}
	warn := Color{255, 0, 0}
	inf  := Color{100, 100, 100}
	good := func(g bool) Color { if g { return ok }; return warn }

	// ── cpu ──────────────────────────────────────────────────────────────────
	addh("cpu")
	gov, govGood := governorSummary()
	addl("governor", gov, good(govGood))
	turboRaw, err := os.ReadFile("/sys/devices/system/cpu/cpufreq/boost")
	if err != nil {
		turboRaw, err = os.ReadFile("/sys/devices/system/cpu/intel_pstate/no_turbo")
	}
	if err == nil {
		v := strings.TrimSpace(string(turboRaw))
		addl("turbo", map[string]string{"1": "enabled", "0": "disabled"}[v], good(v == "1"))
	} else {
		addn("turbo")
	}
	irqbal := checkServiceRunning("irqbalance")
	addl("irqbalance", map[bool]string{true: "running", false: "stopped"}[irqbal], good(irqbal))
	nohz := readSysctlOpt("kernel.nohz_full")
	if nohz != "?" {
		addl("nohz_full", nohz, inf)
	}

	// ── memory ───────────────────────────────────────────────────────────────
	addh("memory")
	swap := readSysctlOpt("vm.swappiness")
	swapN, _ := strconv.Atoi(swap)
	addl("vm.swappiness", swap, good(swapN <= 20))
	dirty := readSysctlOpt("vm.dirty_ratio")
	dirtyBg := readSysctlOpt("vm.dirty_background_ratio")
	addl("dirty_ratio/bg", dirty+"/"+dirtyBg, inf)
	thp := checkTHP()
	addl("transparent_hugepage", thp, good(thp == "madvise" || thp == "never"))
	overcommit := readSysctlOpt("vm.overcommit_memory")
	addl("overcommit_memory", map[string]string{"0": "heuristic", "1": "always", "2": "strict"}[overcommit]+" ("+overcommit+")", good(overcommit != "1"))
	compaction := readSysctlOpt("vm.compaction_proactiveness")
	if compaction != "?" {
		cN, _ := strconv.Atoi(compaction)
		addl("compaction_proactive", compaction, good(cN > 0))
	}

	// ── i/o ──────────────────────────────────────────────────────────────────
	addh("i/o")
	for _, sched := range ioSchedulers() {
		parts := strings.SplitN(sched, ":", 2)
		if len(parts) != 2 {
			continue
		}
		dev, sc := parts[0], parts[1]
		ra := readAheadKB(dev)
		val := sc
		if ra >= 0 {
			val += fmt.Sprintf("  ra:%dkb", ra)
		}
		addl(dev, val, good(sc == "none" || sc == "mq-deadline" || sc == "kyber"))
	}
	nrReq := readSysctlOpt("block.nr_requests")
	if nrReq != "?" {
		addl("nr_requests", nrReq, inf)
	}

	// ── network ──────────────────────────────────────────────────────────────
	addh("network")
	cc := readSysctlOpt("net.ipv4.tcp_congestion_control")
	addl("tcp_congestion", cc, good(cc == "bbr" || cc == "bbr2"))
	rmem := readSysctlOpt("net.core.rmem_max")
	wmem := readSysctlOpt("net.core.wmem_max")
	rmemN, _ := strconv.Atoi(rmem)
	wmemN, _ := strconv.Atoi(wmem)
	addl("socket_buf rx/tx", fmt.Sprintf("%s/%s", fmtBufSize(rmemN), fmtBufSize(wmemN)), good(rmemN >= 4*1024*1024))
	tfo := readSysctlOpt("net.ipv4.tcp_fastopen")
	addl("tcp_fastopen", map[string]string{"0": "off", "1": "client", "2": "server", "3": "both"}[tfo]+" ("+tfo+")", good(tfo == "3"))
	ts := readSysctlOpt("net.ipv4.tcp_timestamps")
	addl("tcp_timestamps", map[string]string{"0": "off", "1": "on"}[ts], good(ts == "1"))
	somaxconn := readSysctlOpt("net.core.somaxconn")
	smN, _ := strconv.Atoi(somaxconn)
	addl("somaxconn", somaxconn, good(smN >= 1024))

	// ── filesystem ───────────────────────────────────────────────────────────
	addh("filesystem")
	inoti := readSysctlOpt("fs.inotify.max_user_watches")
	iN, _ := strconv.Atoi(inoti)
	addl("inotify.max_watches", inoti, good(iN >= 65536))
	fdNr := readSysctlOpt("fs.file-nr")
	if f := strings.Fields(fdNr); len(f) > 0 {
		addl("open_file_handles", f[0], inf)
	}
	noatimeMounts := 0
	if raw, err := os.ReadFile("/proc/mounts"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, "noatime") || strings.Contains(line, "relatime") {
				noatimeMounts++
			}
		}
	}
	addl("noatime/relatime mounts", fmt.Sprintf("%d", noatimeMounts), good(noatimeMounts > 0))

	return lines
}

func drawOPT(buf *strings.Builder, rows, cols int, ss *SysState, ui *UI, t *Theme) {
	hdr := " DEV · OPT " + strings.Repeat("─", max(0, cols-11))
	buf.WriteString(pos(0, 0))
	buf.WriteString(ansiCol(t.HDR) + BOLD + clampStr(hdr, cols) + RESET + CLEOL)

	lines, _ := bgOPT.get(collectOPT)

	// same multi-column layout as SEC
	nCols := 1
	if cols >= 140 {
		nCols = 3
	} else if cols >= 80 {
		nCols = 2
	}

	type span struct{ s, e int }
	var sections []span
	secStart := 0
	for i, l := range lines {
		if i > 0 && l.Bold {
			sections = append(sections, span{secStart, i})
			secStart = i
		}
	}
	sections = append(sections, span{secStart, len(lines)})

	totalLines := len(lines)
	targetH := (totalLines + nCols - 1) / nCols
	colData := make([][]ColLine, nCols)
	ci := 0
	curH := 0
	for _, sp := range sections {
		h := sp.e - sp.s
		if ci < nCols-1 && curH > 0 && curH+h > targetH {
			ci++
			curH = 0
		}
		colData[ci] = append(colData[ci], lines[sp.s:sp.e]...)
		curH += h
	}

	widths := make([]int, nCols)
	for i, col := range colData {
		w := 10
		for _, l := range col {
			if vl := visualLen(l.Text); vl > w {
				w = vl
			}
		}
		widths[i] = w + 1
	}
	used := 0
	for i := 0; i < nCols-1; i++ {
		used += widths[i]
	}
	if rem := cols - used; rem > widths[nCols-1] {
		widths[nCols-1] = rem
	}
	total := 0
	for _, w := range widths {
		total += w
	}
	if total > cols {
		even := cols / nCols
		for i := range widths {
			widths[i] = even
		}
		widths[nCols-1] = cols - even*(nCols-1)
	}

	displayRows := rows - 2
	maxColH := 0
	for _, col := range colData {
		if len(col) > maxColH {
			maxColH = len(col)
		}
	}
	maxScroll := max(0, maxColH-displayRows)
	if ui.OptScroll > maxScroll {
		ui.OptScroll = maxScroll
	}

	for row := 0; row < displayRows; row++ {
		buf.WriteString(pos(row+1, 0))
		for ci, col := range colData {
			w := widths[ci]
			idx := ui.OptScroll + row
			if idx < len(col) {
				l := col[idx]
				if l.Pre {
					clamped := clampVisual(l.Text, w)
					pad := strings.Repeat(" ", max(0, w-visualLen(clamped)))
					buf.WriteString(clamped + pad + RESET)
				} else {
					runes := []rune(l.Text)
					if len(runes) > w {
						runes = runes[:w]
					}
					text := string(runes) + strings.Repeat(" ", max(0, w-len(runes)))
					attr := ansiCol(t.HDR)
					if l.Bold {
						attr = BOLD + attr
					}
					buf.WriteString(attr + text + RESET)
				}
			} else {
				buf.WriteString(strings.Repeat(" ", w))
			}
		}
		buf.WriteString(CLEOL)
	}

	drawStatusBar(buf, rows, cols, ui, ui.Interval, ss, t)
}
