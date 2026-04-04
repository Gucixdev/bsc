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

type optItem struct {
	label string
	val   string
	good  bool
	note  string
	dim   bool
}

func collectOPT() []optItem {
	var items []optItem

	section := func(name string) {
		items = append(items, optItem{label: "\x00" + name})
	}
	add := func(label, val string, good bool, note string) {
		items = append(items, optItem{label: label, val: val, good: good, note: note})
	}
	na := func(label string) {
		items = append(items, optItem{label: label, val: "n/a", good: true, dim: true})
	}

	// ── CPU ──────────────────────────────────────────────────────────────────
	section("cpu")
	gov, govGood := governorSummary()
	add("governor", gov, govGood, "performance or schedutil recommended")
	turboRaw, err := os.ReadFile("/sys/devices/system/cpu/cpufreq/boost")
	if err != nil {
		turboRaw, err = os.ReadFile("/sys/devices/system/cpu/intel_pstate/no_turbo")
	}
	if err == nil {
		v := strings.TrimSpace(string(turboRaw))
		add("turbo", map[string]string{"1": "enabled", "0": "disabled"}[v], v == "1", "")
	} else {
		na("turbo")
	}
	irqbal := checkServiceRunning("irqbalance")
	add("irqbalance", map[bool]string{true: "running", false: "stopped"}[irqbal], irqbal, "spreads IRQs across cores")
	nohz := readSysctlOpt("kernel.nohz_full")
	if nohz != "?" {
		add("nohz_full", nohz, nohz != "", "")
	}

	// ── memory ───────────────────────────────────────────────────────────────
	section("memory")
	swap := readSysctlOpt("vm.swappiness")
	swapN, _ := strconv.Atoi(swap)
	add("vm.swappiness", swap, swapN <= 20, fmt.Sprintf("current:%s  desktop≤10 server≤5", swap))

	dirty := readSysctlOpt("vm.dirty_ratio")
	dirtyBg := readSysctlOpt("vm.dirty_background_ratio")
	add("dirty_ratio", dirty+"/"+dirtyBg, true, "write_ratio/background_ratio")

	thp := checkTHP()
	thpGood := thp == "madvise" || thp == "never"
	add("transparent_hugepage", thp, thpGood, "madvise for low latency, always for throughput")

	overcommit := readSysctlOpt("vm.overcommit_memory")
	add("overcommit_memory", map[string]string{"0": "heuristic", "1": "always", "2": "strict"}[overcommit]+" ("+overcommit+")", overcommit != "1", "")

	compaction := readSysctlOpt("vm.compaction_proactiveness")
	if compaction != "?" {
		cN, _ := strconv.Atoi(compaction)
		add("compaction_proactiveness", compaction, cN > 0, "higher = less fragmentation")
	}

	// ── i/o ──────────────────────────────────────────────────────────────────
	section("i/o")
	for _, sched := range ioSchedulers() {
		parts := strings.SplitN(sched, ":", 2)
		if len(parts) != 2 {
			continue
		}
		dev, sc := parts[0], parts[1]
		goodSched := sc == "none" || sc == "mq-deadline" || sc == "kyber"
		ra := readAheadKB(dev)
		raStr := ""
		if ra >= 0 {
			raStr = fmt.Sprintf("  read_ahead:%dkb", ra)
		}
		add(dev, sc+raStr, goodSched, "none/mq-deadline for SSD, bfq for HDD")
	}
	nrReq := readSysctlOpt("block.nr_requests")
	if nrReq != "?" {
		add("nr_requests", nrReq, true, "")
	}

	// ── network ──────────────────────────────────────────────────────────────
	section("network")
	cc := readSysctlOpt("net.ipv4.tcp_congestion_control")
	add("tcp_congestion", cc, cc == "bbr" || cc == "bbr2", "bbr recommended for most workloads")

	rmem := readSysctlOpt("net.core.rmem_max")
	wmem := readSysctlOpt("net.core.wmem_max")
	rmemN, _ := strconv.Atoi(rmem)
	wmemN, _ := strconv.Atoi(wmem)
	add("socket buffers", fmt.Sprintf("rx:%s tx:%s", fmtBufSize(rmemN), fmtBufSize(wmemN)), rmemN >= 4*1024*1024, "≥4MB recommended for high throughput")

	tfo := readSysctlOpt("net.ipv4.tcp_fastopen")
	add("tcp_fastopen", map[string]string{"0": "off", "1": "client", "2": "server", "3": "both"}[tfo]+" ("+tfo+")", tfo == "3", "3=client+server")

	ts := readSysctlOpt("net.ipv4.tcp_timestamps")
	add("tcp_timestamps", map[string]string{"0": "off", "1": "on"}[ts], ts == "1", "needed for PAWS/RTTM")

	somaxconn := readSysctlOpt("net.core.somaxconn")
	smN, _ := strconv.Atoi(somaxconn)
	add("somaxconn", somaxconn, smN >= 1024, "≥1024 for busy servers")

	// ── filesystem ───────────────────────────────────────────────────────────
	section("filesystem")
	inoti := readSysctlOpt("fs.inotify.max_user_watches")
	iN, _ := strconv.Atoi(inoti)
	add("inotify.max_user_watches", inoti, iN >= 65536, "≥65536 for IDEs/large projects")

	fdNr := readSysctlOpt("fs.file-nr")
	if f := strings.Fields(fdNr); len(f) > 0 {
		add("open file handles", f[0], true, "")
	}

	noatimeMounts := 0
	if raw, err := os.ReadFile("/proc/mounts"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, "noatime") || strings.Contains(line, "relatime") {
				noatimeMounts++
			}
		}
	}
	add("noatime/relatime mounts", fmt.Sprintf("%d", noatimeMounts), noatimeMounts > 0, "reduces disk writes")

	return items
}

func drawOPT(buf *strings.Builder, rows, cols int, ss *SysState, ui *UI, t *Theme) {
	hdr := " DEV · OPT " + strings.Repeat("─", max(0, cols-11))
	buf.WriteString(pos(0, 0))
	buf.WriteString(ansiCol(t.HDR) + BOLD + clampStr(hdr, cols) + RESET + CLEOL)

	ok   := t.DISK
	warn := t.WARN
	inf  := t.USB

	bc := func(good bool) Color {
		if good { return ok }
		return warn
	}

	items, loading := bgOPT.get(collectOPT)

	contentRows := rows - 2
	maxScroll := max(0, len(items)-contentRows)
	if ui.OptScroll > maxScroll {
		ui.OptScroll = maxScroll
	}

	dim := DIM + ansiCol(t.USB)
	for r := 0; r < contentRows; r++ {
		idx := ui.OptScroll + r
		buf.WriteString(pos(r+1, 0))
		if idx >= len(items) {
			buf.WriteString(CLEOL)
			continue
		}
		it := items[idx]
		var line string
		if strings.HasPrefix(it.label, "\x00") {
			name := it.label[1:]
			line = ansiCol(t.HDR) + BOLD + name + RESET + ansiCol(t.HDR) +
				strings.Repeat("─", max(0, cols-len(name)-1)) + RESET
		} else {
			col := bc(it.good)
			if it.dim {
				line = dim + fmt.Sprintf("  %-28s  %s", it.label, it.val) + RESET
			} else {
				status := ansiCol(col)
				note := ""
				if it.note != "" {
					note = dim + "  # " + it.note + RESET
				}
				line = ansiCol(inf) + fmt.Sprintf("  %-28s  ", it.label) + RESET +
					status + it.val + RESET + note
			}
		}
		buf.WriteString(clampVisual(line, cols) + CLEOL)
	}

	_ = loading
	drawStatusBar(buf, rows, cols, ui, ui.Interval, ss, t)
}
