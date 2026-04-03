package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type asmLine struct {
	addr  uint64
	op    string
	args  string
	fn    string // non-empty = function label line
}

type asmEntry struct {
	pid     int
	lines   []asmLine
	loading bool
	err     string
	loaded  time.Time
}

var (
	asmMu    sync.Mutex
	asmCache asmEntry
)

func loadASM(pid int) {
	asmMu.Lock()
	if asmCache.pid == pid && (asmCache.loading || time.Since(asmCache.loaded) < 60*time.Second) {
		asmMu.Unlock()
		return
	}
	asmCache = asmEntry{pid: pid, loading: true}
	asmMu.Unlock()

	go func() {
		exe := fmt.Sprintf("/proc/%d/exe", pid)

		// check exe is accessible
		if _, statErr := os.Lstat(exe); statErr != nil {
			asmMu.Lock()
			asmCache = asmEntry{pid: pid, err: "no exe: " + statErr.Error(), loaded: time.Now()}
			asmMu.Unlock()
			return
		}

		objdump, _ := exec.LookPath("objdump")
		if objdump == "" {
			for _, p := range []string{"/usr/bin/objdump", "/usr/local/bin/objdump", "/bin/objdump"} {
				if _, e := os.Stat(p); e == nil {
					objdump = p
					break
				}
			}
		}

		var lines []asmLine
		var errStr string
		if objdump == "" {
			errStr = "objdump not found — install binutils"
		}
		if errStr == "" {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, objdump, "-d", "--no-show-raw-insn", "-M", "intel", exe).CombinedOutput()
			if err != nil {
				out, err = exec.CommandContext(ctx, objdump, "-d", "--no-show-raw-insn", exe).CombinedOutput()
			}
			if err != nil {
				// show first line of combined output for context
				msg := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
				if msg == "" {
					msg = err.Error()
				}
				errStr = msg
			} else {
				lines = parseObjdump(string(out))
			}
		}
		asmMu.Lock()
		asmCache = asmEntry{pid: pid, lines: lines, loading: false, err: errStr, loaded: time.Now()}
		asmMu.Unlock()
	}()
}

func parseObjdump(raw string) []asmLine {
	var out []asmLine
	for _, line := range strings.Split(raw, "\n") {
		// function label: "deadbeef <name>:"
		if strings.Contains(line, "<") && strings.HasSuffix(strings.TrimSpace(line), ">:") {
			trimmed := strings.TrimSpace(line)
			sp := strings.Index(trimmed, " ")
			if sp < 0 {
				continue
			}
			addrStr := trimmed[:sp]
			addr, err := strconv.ParseUint(addrStr, 16, 64)
			if err != nil {
				continue
			}
			fnName := trimmed[sp+2 : len(trimmed)-2] // strip " <" and ">:"
			out = append(out, asmLine{addr: addr, fn: fnName})
			continue
		}
		// instruction: "  addr:	opcode  args"
		trimmed := strings.TrimLeft(line, " \t")
		if !strings.Contains(trimmed, ":") {
			continue
		}
		colonIdx := strings.Index(trimmed, ":")
		addrStr := trimmed[:colonIdx]
		addr, err := strconv.ParseUint(addrStr, 16, 64)
		if err != nil {
			continue
		}
		rest := strings.TrimSpace(trimmed[colonIdx+1:])
		// strip inline comment after ";"
		if semi := strings.Index(rest, ";"); semi >= 0 {
			rest = strings.TrimSpace(rest[:semi])
		}
		f := strings.Fields(rest)
		op, args := "", ""
		if len(f) > 0 {
			op = f[0]
		}
		if len(f) > 1 {
			args = strings.Join(f[1:], " ")
		}
		if op == "" {
			continue
		}
		out = append(out, asmLine{addr: addr, op: op, args: args})
	}
	return out
}

func asmOpColor(op string, t *Theme) string {
	op = strings.ToLower(op)
	// control flow
	if strings.HasPrefix(op, "j") || op == "call" || op == "ret" ||
		op == "retq" || op == "retl" || strings.HasPrefix(op, "loop") {
		return ansiCol(t.WARN)
	}
	// memory / stack
	if strings.HasPrefix(op, "mov") || op == "push" || op == "pop" ||
		op == "lea" || op == "xchg" || op == "pushq" || op == "popq" {
		return ansiCol(t.RAM)
	}
	// syscall / int
	if op == "syscall" || op == "int" || op == "sysenter" {
		return ansiCol(t.GPU)
	}
	return ansiCol(t.DISK)
}

func drawASM(buf *strings.Builder, rows, cols int, ss *SysState, ui *UI, t *Theme) {
	dim := DIM + ansiCol(t.USB)

	// pick a PID to show
	pid := ui.AsmPID
	if pid == 0 {
		ss.mu.RLock()
		if len(ss.Procs) > 0 {
			pid = ss.Procs[0].PID
			ui.AsmPID = pid
		}
		ss.mu.RUnlock()
	}

	// header
	pidStr := "none"
	if pid != 0 {
		pidStr = fmt.Sprintf("%d", pid)
		// find comm
		ss.mu.RLock()
		for _, p := range ss.Procs {
			if p.PID == pid {
				pidStr = fmt.Sprintf("%d (%s)", pid, p.Comm)
				break
			}
		}
		ss.mu.RUnlock()
	}
	hdr := fmt.Sprintf(" ASM  pid:%s", pidStr)
	hdr = clampStr(hdr+strings.Repeat("─", max(0, cols-len(hdr))), cols)
	buf.WriteString(pos(0, 0))
	buf.WriteString(ansiCol(t.HDR) + BOLD + hdr + RESET + CLEOL)

	contentRows := rows - 3

	if pid == 0 {
		buf.WriteString(pos(2, 0))
		buf.WriteString(dim + "  select process in OVW (Enter), then switch to ASM tab" + RESET + CLEOL)
		for r := 3; r < rows-2; r++ {
			buf.WriteString(pos(r, 0) + CLEOL)
		}
		drawHints(buf, rows-2, cols, ui, t)
		return
	}

	loadASM(pid)

	asmMu.Lock()
	cache := asmCache
	asmMu.Unlock()

	if cache.pid != pid || cache.loading {
		buf.WriteString(pos(2, 0))
		buf.WriteString(dim + "  disassembling..." + RESET + CLEOL)
		for r := 3; r < rows-2; r++ {
			buf.WriteString(pos(r, 0) + CLEOL)
		}
		drawHints(buf, rows-2, cols, ui, t)
		return
	}

	if cache.err != "" {
		buf.WriteString(pos(2, 0))
		buf.WriteString(ansiCol(t.WARN) + "  " + cache.err + RESET + CLEOL)
		for r := 4; r < rows-2; r++ {
			buf.WriteString(pos(r, 0) + CLEOL)
		}
		drawHints(buf, rows-2, cols, ui, t)
		return
	}

	lines := cache.lines
	maxScroll := len(lines) - contentRows
	if maxScroll < 0 {
		maxScroll = 0
	}
	if ui.AsmScroll > maxScroll {
		ui.AsmScroll = maxScroll
	}
	if ui.AsmScroll < 0 {
		ui.AsmScroll = 0
	}

	for r := 0; r < contentRows; r++ {
		idx := ui.AsmScroll + r
		buf.WriteString(pos(r+1, 0))
		if idx >= len(lines) {
			buf.WriteString(CLEOL)
			continue
		}
		l := lines[idx]
		var s string
		if l.fn != "" {
			s = ansiCol(t.DISK) + BOLD + fmt.Sprintf(" %016x  <%s>", l.addr, l.fn) + RESET
		} else {
			opCol := asmOpColor(l.op, t)
			s = DIM + ansiCol(t.DISK) + fmt.Sprintf(" %016x  ", l.addr) + RESET +
				opCol + fmt.Sprintf("%-10s", l.op) + RESET +
				ansiCol(t.DISK) + l.args + RESET
		}
		buf.WriteString(clampVisual(s, cols) + CLEOL)
	}

	// info bar: line count + position
	buf.WriteString(pos(rows-2, 0))
	total := len(lines)
	pct := 0
	if total > 0 {
		pct = (ui.AsmScroll + contentRows/2) * 100 / total
	}
	infoStr := fmt.Sprintf(" %d lines  %d%%", total, pct)

	// build function index for quick nav info
	fnCount := 0
	for _, l := range lines {
		if l.fn != "" {
			fnCount++
		}
	}
	infoStr += fmt.Sprintf("  %d functions", fnCount)
	buf.WriteString(dim + clampStr(infoStr, cols) + RESET + CLEOL)

	drawHints(buf, rows-1, cols, ui, t)
}

// asmNextFn — scroll to next function label
func asmNextFn(ui *UI, lines []asmLine, dir int) {
	if len(lines) == 0 {
		return
	}
	start := ui.AsmScroll
	n := len(lines)
	for i := 1; i < n; i++ {
		idx := (start + dir*i + n*n) % n
		if lines[idx].fn != "" {
			ui.AsmScroll = idx
			return
		}
	}
}

// asmPIDList — sorted list of visible PIDs
func asmPIDList(ss *SysState) []int {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	var pids []int
	for _, p := range ss.Procs {
		pids = append(pids, p.PID)
	}
	sort.Ints(pids)
	return pids
}

func asmSelectPID(ui *UI, ss *SysState, dir int) {
	pids := asmPIDList(ss)
	if len(pids) == 0 {
		return
	}
	cur := ui.AsmPID
	for i, p := range pids {
		if p == cur {
			next := i + dir
			if next < 0 {
				next = 0
			}
			if next >= len(pids) {
				next = len(pids) - 1
			}
			if pids[next] != cur {
				ui.AsmPID = pids[next]
				ui.AsmScroll = 0
			}
			return
		}
	}
	// cur not found, pick first
	ui.AsmPID = pids[0]
	ui.AsmScroll = 0
}

// hexSaveDump — save current hex view to /tmp/bsc-dump-<timestamp>.bin
func hexSaveDump(ss *SysState, ui *UI) {
	var data []byte
	switch ui.HexSource {
	case HEX_MEM:
		regions := parseMaps(ui.HexPID)
		if ui.HexRegion < len(regions) {
			r := regions[ui.HexRegion]
			f, err := os.Open(fmt.Sprintf("/proc/%d/mem", ui.HexPID))
			if err != nil {
				return
			}
			defer f.Close()
			size := r.End - r.Start
			if size > 16*1024*1024 {
				size = 16 * 1024 * 1024
			}
			data = make([]byte, size)
			f.ReadAt(data, r.Start)
		}
	case HEX_VRAM:
		vm := openVRAMBar()
		if vm.err == "" {
			sz := int64(16 * 1024 * 1024)
			if int64(len(vm.data)) < sz {
				sz = int64(len(vm.data))
			}
			data = make([]byte, sz)
			copy(data, vm.data[:sz])
		}
	}
	if len(data) == 0 {
		return
	}
	path := fmt.Sprintf("/tmp/bsc-dump-%d.bin", time.Now().Unix())
	os.WriteFile(path, data, 0600)
}
