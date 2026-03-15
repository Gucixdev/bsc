package main

// bsc — bullshit control v2 (Go rewrite)
// devlog: iter1 — raw terminal + ANSI draw + OVW: CPU/RAM/procs
// todo: iter2 disk/net/gpu/usb/vms, iter3 DEV tab, iter4 HEX tab

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// ── CONSTANTS ────────────────────────────────────────────────────────────────

const (
	FPS   = 30
	HZ    = 100 // Linux USER_HZ
	FRAME = time.Second / FPS

	TAB_OVW = 0
	TAB_DEV = 1
	TAB_HEX = 2

	SORT_CPU = "cpu"
	SORT_MEM = "mem"
)

// ANSI primitives — no curses
const (
	RESET   = "\033[0m"
	BOLD    = "\033[1m"
	DIM     = "\033[2m"
	REV     = "\033[7m"
	CLRSCR  = "\033[2J"
	HOME    = "\033[H"
	HIDECUR = "\033[?25l"
	SHOWCUR = "\033[?25h"
	SYNCON  = "\033[?2026h"
	SYNCOFF = "\033[?2026l"
	CLEOL   = "\033[K"
)

func pos(row, col int) string    { return fmt.Sprintf("\033[%d;%dH", row+1, col+1) }
func fgRGB(r, g, b uint8) string { return fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b) }
func bgRGB(r, g, b uint8) string { return fmt.Sprintf("\033[48;2;%d;%d;%dm", r, g, b) }
func fg256(n int) string         { return fmt.Sprintf("\033[38;5;%dm", n) }

// ── COLOR SYSTEM ─────────────────────────────────────────────────────────────

type Color [3]uint8

type Theme struct {
	HDR, CPU, GPU, RAM, ZRAM, DISK, NET, SEL, USB, MARK, WARN Color
}

var defaultTheme = Theme{
	HDR:  Color{0xff, 0x87, 0x00},
	CPU:  Color{0x87, 0x00, 0xff},
	GPU:  Color{0x00, 0xff, 0x5f},
	RAM:  Color{0xff, 0xd7, 0x00},
	ZRAM: Color{0xaf, 0x87, 0xff},
	DISK: Color{0x00, 0xff, 0x5f},
	NET:  Color{0x00, 0x87, 0xff},
	SEL:  Color{0xff, 0xff, 0x00},
	USB:  Color{0x8a, 0x8a, 0x8a},
	MARK: Color{0xff, 0x87, 0x00},
	WARN: Color{0xff, 0x00, 0x00},
}

var truecolor bool

func loadTheme() Theme {
	path := os.Getenv("HOME") + "/.config/bsc/theme.json"
	f, err := os.Open(path)
	if err != nil {
		return defaultTheme
	}
	defer f.Close()
	var raw map[string]string
	if json.NewDecoder(f).Decode(&raw) != nil {
		return defaultTheme
	}
	t := defaultTheme
	set := func(dst *Color, key string) {
		v, ok := raw[key]
		if !ok || len(v) != 7 || v[0] != '#' {
			return
		}
		r, _ := strconv.ParseUint(v[1:3], 16, 8)
		g, _ := strconv.ParseUint(v[3:5], 16, 8)
		b, _ := strconv.ParseUint(v[5:7], 16, 8)
		*dst = Color{uint8(r), uint8(g), uint8(b)}
	}
	set(&t.HDR, "HDR"); set(&t.CPU, "CPU"); set(&t.GPU, "GPU")
	set(&t.RAM, "RAM"); set(&t.ZRAM, "ZRAM"); set(&t.DISK, "DISK")
	set(&t.NET, "NET"); set(&t.SEL, "SEL"); set(&t.USB, "USB")
	set(&t.MARK, "MARK"); set(&t.WARN, "WARN")
	return t
}

// ansiCol → fg color escape; integer-only 256-color fallback (no math import)
func ansiCol(c Color) string {
	if truecolor {
		return fgRGB(c[0], c[1], c[2])
	}
	ri := (int(c[0])*5 + 127) / 255
	gi := (int(c[1])*5 + 127) / 255
	bi := (int(c[2])*5 + 127) / 255
	return fg256(16 + 36*ri + 6*gi + bi)
}

func pctColor(pct float64, t *Theme) Color {
	if pct >= 80 {
		return t.WARN
	}
	if pct >= 50 {
		return t.RAM
	}
	return t.DISK
}

// ── TERMINAL ─────────────────────────────────────────────────────────────────

var origT syscall.Termios

func rawOn() {
	syscall.Syscall(syscall.SYS_IOCTL, 0, syscall.TCGETS, uintptr(unsafe.Pointer(&origT)))
	raw := origT
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Iflag &^= syscall.IXON | syscall.ICRNL | syscall.BRKINT | syscall.INPCK | syscall.ISTRIP
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 0
	raw.Cc[syscall.VTIME] = 1 // 100ms read timeout
	syscall.Syscall(syscall.SYS_IOCTL, 0, syscall.TCSETS, uintptr(unsafe.Pointer(&raw)))
	os.Stdout.WriteString(HIDECUR)
}

func rawOff() {
	syscall.Syscall(syscall.SYS_IOCTL, 0, syscall.TCSETS, uintptr(unsafe.Pointer(&origT)))
	os.Stdout.WriteString(SHOWCUR + RESET + "\n")
}

// winsize mirrors struct winsize from <sys/ioctl.h> — no syscall.Winsize in Go stdlib
type winsize struct {
	Row, Col       uint16
	Xpixel, Ypixel uint16
}

func winSize() (int, int) {
	var ws winsize
	syscall.Syscall(syscall.SYS_IOCTL, 1, syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	r, c := int(ws.Row), int(ws.Col)
	if r < 1 {
		r = 24
	}
	if c < 1 {
		c = 80
	}
	return r, c
}

// ── TYPES ────────────────────────────────────────────────────────────────────

type CoreStat struct {
	Pct      float64
	FreqMHz  int
	TempC    int
	Turbo    bool
	Throttle int
}

type MemStat struct {
	TotalKB, UsedKB       int
	SwapTotKB, SwapUsedKB int
	ZramTotKB, ZramUsedKB int
}

type ProcStat struct {
	PID   int
	Comm  string
	Cmd   string
	UID   int
	CPU   float64
	MemKB int
	State string
}

// SysState — collected data; mu protects all fields
type SysState struct {
	mu       sync.RWMutex
	Cores    []CoreStat
	Load     [3]float64
	RaplW    float64
	Mem      MemStat
	Procs    []ProcStat
	ProcCnts map[string]int
}

// UI — only touched by main goroutine (no mutex needed)
type UI struct {
	Tab      int
	Interval time.Duration
	Sel      int
	Scroll   int
	Sort     string
	Filter   string // user | root | kern | all
}

// ── COLLECTION ───────────────────────────────────────────────────────────────

var (
	prevCPURaw [][]int64
	prevProcJ  map[int]int64
	prevProcT  time.Time
	prevRaplUJ int64
	prevRaplT  time.Time
)

func readCPU() ([]CoreStat, [3]float64, float64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return nil, [3]float64{}, 0
	}
	defer f.Close()

	var cur [][]int64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu") || strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		row := make([]int64, 7)
		for i := 0; i < 7; i++ {
			row[i], _ = strconv.ParseInt(fields[i+1], 10, 64)
		}
		cur = append(cur, row)
	}

	pcts := make([]float64, len(cur))
	if prevCPURaw != nil && len(prevCPURaw) == len(cur) {
		for i, n := range cur {
			p := prevCPURaw[i]
			var totDelta, idleDelta int64
			for j := 0; j < 7; j++ {
				totDelta += n[j] - p[j]
			}
			idleDelta = n[3] - p[3]
			if totDelta > 0 {
				pcts[i] = float64(totDelta-idleDelta) / float64(totDelta) * 100
			}
		}
	}
	prevCPURaw = cur

	// coretemp hwmon
	temps := map[int]int{}
	hwdir, _ := os.ReadDir("/sys/class/hwmon")
	for _, hw := range hwdir {
		base := "/sys/class/hwmon/" + hw.Name()
		nameb, _ := os.ReadFile(base + "/name")
		if strings.TrimSpace(string(nameb)) != "coretemp" {
			continue
		}
		entries, _ := os.ReadDir(base)
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, "_label") || !strings.HasPrefix(n, "temp") {
				continue
			}
			num := strings.TrimPrefix(strings.TrimSuffix(n, "_label"), "temp")
			lbl, _ := os.ReadFile(base + "/" + n)
			lbls := strings.TrimSpace(string(lbl))
			if !strings.HasPrefix(lbls, "Core ") {
				continue
			}
			coreN, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(lbls, "Core ")))
			if err != nil {
				continue
			}
			tinput, _ := os.ReadFile(base + "/temp" + num + "_input")
			t, _ := strconv.Atoi(strings.TrimSpace(string(tinput)))
			temps[coreN] = t / 1000
		}
	}

	freqs := map[int]int{}
	baseFreqs := map[int]int{}
	throttles := map[int]int{}
	cpuDir, _ := os.ReadDir("/sys/devices/system/cpu")
	for _, e := range cpuDir {
		name := e.Name()
		if !strings.HasPrefix(name, "cpu") {
			continue
		}
		n, err := strconv.Atoi(name[3:])
		if err != nil {
			continue
		}
		base := "/sys/devices/system/cpu/" + name
		if v, err := os.ReadFile(base + "/cpufreq/scaling_cur_freq"); err == nil {
			f, _ := strconv.Atoi(strings.TrimSpace(string(v)))
			freqs[n] = f / 1000
		}
		if v, err := os.ReadFile(base + "/cpufreq/base_frequency"); err == nil {
			f, _ := strconv.Atoi(strings.TrimSpace(string(v)))
			baseFreqs[n] = f / 1000
		}
		if v, err := os.ReadFile(base + "/thermal_throttle/core_throttle_count"); err == nil {
			f, _ := strconv.Atoi(strings.TrimSpace(string(v)))
			throttles[n] = f
		}
	}

	cores := make([]CoreStat, len(pcts))
	for i, p := range pcts {
		t := temps[i]
		if t == 0 {
			t = temps[i/2]
		}
		curF := freqs[i]
		baseF := baseFreqs[i]
		cores[i] = CoreStat{
			Pct:      p,
			FreqMHz:  curF,
			TempC:    t,
			Turbo:    curF > 0 && baseF > 0 && curF > baseF,
			Throttle: throttles[i],
		}
	}

	var load [3]float64
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			load[0], _ = strconv.ParseFloat(fields[0], 64)
			load[1], _ = strconv.ParseFloat(fields[1], 64)
			load[2], _ = strconv.ParseFloat(fields[2], 64)
		}
	}

	// RAPL power — ujoules delta / dt / 1e6 = watts
	var raplW float64
	if data, err := os.ReadFile("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj"); err == nil {
		uj, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		now := time.Now()
		if !prevRaplT.IsZero() {
			dt := now.Sub(prevRaplT).Seconds()
			if dt > 0 {
				raplW = float64(uj-prevRaplUJ) / dt / 1e6
			}
		}
		prevRaplUJ = uj
		prevRaplT = now
	}

	return cores, load, raplW
}

func readMem() MemStat {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return MemStat{}
	}
	defer f.Close()

	mi := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := line[:colon]
		val := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line[colon+1:]), "kB"))
		mi[key], _ = strconv.Atoi(val)
	}

	var zt, zu int
	if data, err := os.ReadFile("/sys/block/zram0/disksize"); err == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		zt = int(v >> 10)
	}
	if data, err := os.ReadFile("/sys/block/zram0/mm_stat"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 2 {
			v, _ := strconv.ParseInt(fields[1], 10, 64)
			zu = int(v >> 10)
		}
	}

	total := mi["MemTotal"]
	avail := mi["MemAvailable"]
	return MemStat{
		TotalKB:    total,
		UsedKB:     total - avail,
		SwapTotKB:  mi["SwapTotal"],
		SwapUsedKB: mi["SwapTotal"] - mi["SwapFree"],
		ZramTotKB:  zt,
		ZramUsedKB: zu,
	}
}

func readProcs() ([]ProcStat, map[string]int) {
	now := time.Now()
	var dt float64
	if !prevProcT.IsZero() {
		dt = now.Sub(prevProcT).Seconds()
	}
	prevProcT = now

	if prevProcJ == nil {
		prevProcJ = make(map[int]int64)
	}

	entries, _ := os.ReadDir("/proc")
	var procs []ProcStat
	newJ := make(map[int]int64, len(prevProcJ))
	counts := map[string]int{}
	pageKB := os.Getpagesize() / 1024

	for _, e := range entries {
		name := e.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		pid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}

		statData, err := os.ReadFile("/proc/" + name + "/stat")
		if err != nil {
			continue
		}

		line := string(statData)
		i := strings.IndexByte(line, '(')
		j := strings.LastIndexByte(line, ')')
		if i < 0 || j <= i {
			continue
		}

		comm := line[i+1 : j]
		rest := strings.Fields(line[j+2:])
		if len(rest) < 22 {
			continue
		}

		state := rest[0]
		counts[state]++

		utime, _ := strconv.ParseInt(rest[11], 10, 64)
		stime, _ := strconv.ParseInt(rest[12], 10, 64)
		rssPages, _ := strconv.ParseInt(rest[21], 10, 64)
		jTotal := utime + stime

		newJ[pid] = jTotal

		var cpuPct float64
		if dt > 0 {
			if prevJ, ok := prevProcJ[pid]; ok {
				cpuPct = float64(jTotal-prevJ) / (dt * HZ) * 100
			}
		}

		var cmd string
		if cmdData, err := os.ReadFile("/proc/" + name + "/cmdline"); err == nil {
			cmd = strings.ReplaceAll(string(cmdData), "\x00", " ")
			cmd = strings.TrimSpace(cmd)
		}
		if cmd == "" {
			cmd = "[" + comm + "]"
		}

		// uid from status — only read Uid line
		var uid int
		if statusData, err := os.ReadFile("/proc/" + name + "/status"); err == nil {
			for _, l := range strings.SplitN(string(statusData), "\n", 50) {
				if strings.HasPrefix(l, "Uid:") {
					fields := strings.Fields(l)
					if len(fields) >= 2 {
						uid, _ = strconv.Atoi(fields[1])
					}
					break
				}
			}
		}

		procs = append(procs, ProcStat{
			PID:   pid,
			Comm:  comm,
			Cmd:   cmd,
			UID:   uid,
			CPU:   cpuPct,
			MemKB: int(rssPages) * pageKB,
			State: state,
		})
	}

	prevProcJ = newJ
	return procs, counts
}

// ── DRAW HELPERS ─────────────────────────────────────────────────────────────

func fmtMem(kb int) string {
	if kb >= 1024*1024 {
		return fmt.Sprintf("%.1fG", float64(kb)/1024/1024)
	}
	if kb >= 1024 {
		return fmt.Sprintf("%dM", kb/1024)
	}
	return fmt.Sprintf("%dK", kb)
}

func pct2(used, total int) int {
	if total == 0 {
		return 0
	}
	p := 100 * used / total
	if p > 100 {
		return 100
	}
	return p
}

// ColLine — one row in a column
type ColLine struct {
	Text string
	C    Color
	Dim  bool
	Bold bool
}

func addLine(lines *[]ColLine, h int, text string, c Color, dim, bold bool) {
	if len(*lines) < h {
		*lines = append(*lines, ColLine{text, c, dim, bold})
	}
}

// renderCols draws columns side-by-side into buf starting at row startRow
func renderCols(buf *strings.Builder, startRow, nRows int, cols [][]ColLine, widths []int, t *Theme) {
	for row := 0; row < nRows; row++ {
		buf.WriteString(pos(startRow+row, 0))
		for ci, lines := range cols {
			w := widths[ci]
			contentW := w
			if ci < len(cols)-1 {
				contentW = w - 1
			}
			var text string
			var attr string
			if row < len(lines) {
				l := lines[row]
				text = l.Text
				runes := []rune(text)
				if len(runes) > contentW {
					text = string(runes[:contentW])
				}
				text = text + strings.Repeat(" ", max(0, contentW-len([]rune(text))))
				attr = ansiCol(l.C)
				if l.Bold {
					attr = BOLD + attr
				}
				if l.Dim {
					attr = DIM + attr
				}
			} else {
				text = strings.Repeat(" ", contentW)
			}
			buf.WriteString(attr)
			buf.WriteString(text)
			buf.WriteString(RESET)
			if ci < len(cols)-1 {
				buf.WriteString(ansiCol(t.HDR))
				buf.WriteString(DIM)
				buf.WriteString("│")
				buf.WriteString(RESET)
			}
		}
		buf.WriteString(CLEOL)
	}
}

// ── COLUMN BUILDERS ──────────────────────────────────────────────────────────

func colCPURAM(cores []CoreStat, load [3]float64, raplW float64, mem MemStat, h int, t *Theme) []ColLine {
	var lines []ColLine
	add := func(text string, c Color, dim, bold bool) {
		addLine(&lines, h, text, c, dim, bold)
	}

	avgPct := 0.0
	for _, c := range cores {
		avgPct += c.Pct
	}
	if len(cores) > 0 {
		avgPct /= float64(len(cores))
	}

	gov := "?"
	if data, err := os.ReadFile("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"); err == nil {
		gov = strings.TrimSpace(string(data))
	}

	cpuC := pctColor(avgPct, t)
	add(fmt.Sprintf("CPU %3.0f%%  ld:%.1f/%.1f/%.1f", avgPct, load[0], load[1], load[2]), cpuC, false, false)
	add(fmt.Sprintf("  %.0fW  %s", raplW, gov), cpuC, false, false)

	for i, c := range cores {
		freqS := "--MHz"
		if c.FreqMHz > 0 {
			freqS = fmt.Sprintf("%dMHz", c.FreqMHz)
		}
		tempS := "--°"
		if c.TempC > 0 {
			tempS = fmt.Sprintf("%d°", c.TempC)
		}
		add(fmt.Sprintf("%2d %3.0f%% | %s | %s", i, c.Pct, freqS, tempS), pctColor(c.Pct, t), false, false)
	}

	if len(cores) > 0 {
		turboN, thrMax := 0, 0
		for _, c := range cores {
			if c.Turbo {
				turboN++
			}
			if c.Throttle > thrMax {
				thrMax = c.Throttle
			}
		}
		add(fmt.Sprintf("turbo:%d/%d thr:%d", turboN, len(cores), thrMax), t.DISK, true, false)
	}

	// separator
	add("", t.USB, true, false)

	mrow := func(lbl string, used, tot int, missing bool) {
		if missing {
			add(fmt.Sprintf("%s --/-- ---", lbl), t.WARN, false, false)
			return
		}
		p := pct2(used, tot)
		add(fmt.Sprintf("%s %6s/%-6s %3d%%", lbl, fmtMem(used), fmtMem(tot), p), pctColor(float64(p), t), false, false)
	}
	mrow("RAM", mem.UsedKB, mem.TotalKB, false)
	mrow("SWP", mem.SwapUsedKB, mem.SwapTotKB, mem.SwapTotKB == 0)
	if mem.ZramTotKB > 0 {
		mrow("ZRM", mem.ZramUsedKB, mem.ZramTotKB, false)
	}

	return lines
}

// ── DRAW OVW ─────────────────────────────────────────────────────────────────

func filterProcs(procs []ProcStat, filter string) []ProcStat {
	out := procs[:0:len(procs)]
	out = out[:0]
	for _, p := range procs {
		isKern := p.Cmd == "["+p.Comm+"]"
		switch filter {
		case "user":
			if p.UID == 0 || isKern {
				continue
			}
		case "root":
			if p.UID != 0 {
				continue
			}
		case "kern":
			if !isKern {
				continue
			}
		}
		out = append(out, p)
	}
	return out
}

func drawOVW(buf *strings.Builder, rows, cols int,
	cores []CoreStat, load [3]float64, raplW float64,
	mem MemStat, allProcs []ProcStat, cnts map[string]int,
	ui *UI, t *Theme) {

	topH := rows / 2
	if topH < 10 {
		topH = 10
	}
	if topH > 22 {
		topH = 22
	}

	// columns: left=CPU+RAM, right=placeholder until iter2
	leftW := 32
	if leftW > cols {
		leftW = cols
	}
	rightW := cols - leftW

	leftLines := colCPURAM(cores, load, raplW, mem, topH, t)

	var rightLines []ColLine
	if rightW > 5 {
		addLine(&rightLines, topH, "DISK/NET/GPU — iter2", t.USB, true, false)
	}

	renderCols(buf, 0, topH, [][]ColLine{leftLines, rightLines}, []int{leftW, rightW}, t)

	// proc section
	procs := filterProcs(allProcs, ui.Filter)

	if ui.Sort == SORT_MEM {
		sort.Slice(procs, func(i, j int) bool { return procs[i].MemKB > procs[j].MemKB })
	} else {
		sort.Slice(procs, func(i, j int) bool { return procs[i].CPU > procs[j].CPU })
	}

	rn := cnts["R"]
	sn := cnts["S"]
	dn := cnts["D"]
	zn := cnts["Z"]
	stats := fmt.Sprintf("R:%d S:%d D:%d Z:%d", rn, sn, dn, zn)
	filt := fmt.Sprintf("◄ %s ►", ui.Filter)
	sl := strings.ToUpper(ui.Sort)
	dashN := cols - len(filt) - len(stats) - len(sl) - 14
	if dashN < 0 {
		dashN = 0
	}
	hdrLine := fmt.Sprintf(" PROC [%s]%s[%s][%s] ", filt, strings.Repeat("─", dashN), stats, sl)
	if len([]rune(hdrLine)) > cols {
		hdrLine = string([]rune(hdrLine)[:cols])
	}

	buf.WriteString(pos(topH, 0))
	buf.WriteString(ansiCol(t.HDR))
	buf.WriteString(BOLD)
	buf.WriteString(hdrLine)
	buf.WriteString(RESET)
	buf.WriteString(CLEOL)

	colHdr := fmt.Sprintf("  %6s  %5s  %6s  T  CMD", "PID", "CPU%", "MEM")
	if len(colHdr) > cols {
		colHdr = colHdr[:cols]
	}
	buf.WriteString(pos(topH+1, 0))
	buf.WriteString(DIM)
	buf.WriteString(colHdr)
	buf.WriteString(RESET)
	buf.WriteString(CLEOL)

	listStart := topH + 2
	avail := rows - listStart - 2
	if avail < 0 {
		avail = 0
	}

	// clamp scroll + sel
	if ui.Scroll < 0 {
		ui.Scroll = 0
	}
	if len(procs) > avail && ui.Scroll > len(procs)-avail {
		ui.Scroll = len(procs) - avail
	}
	if ui.Sel < 0 {
		ui.Sel = 0
	}
	if ui.Sel >= len(procs) && len(procs) > 0 {
		ui.Sel = len(procs) - 1
	}
	// auto-scroll to keep sel visible
	if ui.Sel < ui.Scroll {
		ui.Scroll = ui.Sel
	}
	if ui.Sel >= ui.Scroll+avail {
		ui.Scroll = ui.Sel - avail + 1
	}

	end := ui.Scroll + avail
	if end > len(procs) {
		end = len(procs)
	}

	for i, p := range procs[ui.Scroll:end] {
		absI := ui.Scroll + i
		isSel := absI == ui.Sel

		var attr string
		switch {
		case isSel:
			attr = bgRGB(t.CPU[0], t.CPU[1], t.CPU[2]) + fgRGB(0, 0, 0) + BOLD
		case p.State == "Z":
			attr = ansiCol(t.WARN) + BOLD
		case p.CPU >= 20:
			attr = ansiCol(t.WARN)
		case p.CPU >= 5:
			attr = ansiCol(t.RAM)
		default:
			attr = ansiCol(t.DISK)
		}

		maxCmd := cols - 33
		if maxCmd < 0 {
			maxCmd = 0
		}
		cmd := p.Cmd
		if len([]rune(cmd)) > maxCmd {
			cmd = string([]rune(cmd)[:maxCmd])
		}

		line := fmt.Sprintf("  %6d  %5.1f  %6s  %s  %s", p.PID, p.CPU, fmtMem(p.MemKB), p.State, cmd)
		if len([]rune(line)) > cols {
			line = string([]rune(line)[:cols])
		}
		// pad to cols so bg color fills the row
		line = line + strings.Repeat(" ", max(0, cols-len([]rune(line))))

		buf.WriteString(pos(listStart+i, 0))
		buf.WriteString(attr)
		buf.WriteString(line)
		buf.WriteString(RESET)
	}

	// clear remaining rows in proc section
	for i := end - ui.Scroll; i < avail; i++ {
		buf.WriteString(pos(listStart+i, 0))
		buf.WriteString(CLEOL)
	}

	// hints row
	hints := "  ↑↓=sel  ←→=flt  c=cpu  m=mem  k=SIGTERM  9=SIGKILL"
	if len(hints) > cols {
		hints = hints[:cols]
	}
	buf.WriteString(pos(rows-2, 0))
	buf.WriteString(ansiCol(t.USB))
	buf.WriteString(DIM)
	buf.WriteString(hints)
	buf.WriteString(RESET)
	buf.WriteString(CLEOL)

	drawStatusBar(buf, rows, cols, ui.Tab, ui.Interval, t)
}

func drawDEV(buf *strings.Builder, rows, cols int, ui *UI, t *Theme) {
	hdr := fmt.Sprintf(" DEV %s", strings.Repeat("─", max(0, cols-5)))
	if len(hdr) > cols {
		hdr = hdr[:cols]
	}
	buf.WriteString(pos(0, 0))
	buf.WriteString(ansiCol(t.HDR))
	buf.WriteString(BOLD)
	buf.WriteString(hdr)
	buf.WriteString(RESET)
	buf.WriteString(CLEOL)

	buf.WriteString(pos(1, 0))
	buf.WriteString(ansiCol(t.USB))
	buf.WriteString(DIM)
	buf.WriteString("DEV tab — iter3")
	buf.WriteString(RESET)
	buf.WriteString(CLEOL)

	for r := 2; r < rows-1; r++ {
		buf.WriteString(pos(r, 0))
		buf.WriteString(CLEOL)
	}
	drawStatusBar(buf, rows, cols, ui.Tab, ui.Interval, t)
}

func drawHEX(buf *strings.Builder, rows, cols int, ui *UI, t *Theme) {
	hdr := fmt.Sprintf(" HEX %s", strings.Repeat("─", max(0, cols-5)))
	if len(hdr) > cols {
		hdr = hdr[:cols]
	}
	buf.WriteString(pos(0, 0))
	buf.WriteString(ansiCol(t.HDR))
	buf.WriteString(BOLD)
	buf.WriteString(hdr)
	buf.WriteString(RESET)
	buf.WriteString(CLEOL)

	buf.WriteString(pos(1, 0))
	buf.WriteString(ansiCol(t.USB))
	buf.WriteString(DIM)
	buf.WriteString("HEX tab — iter4")
	buf.WriteString(RESET)
	buf.WriteString(CLEOL)

	for r := 2; r < rows-1; r++ {
		buf.WriteString(pos(r, 0))
		buf.WriteString(CLEOL)
	}
	drawStatusBar(buf, rows, cols, ui.Tab, ui.Interval, t)
}

func drawStatusBar(buf *strings.Builder, rows, cols, tab int, interval time.Duration, t *Theme) {
	tabs := "[1=OVW 2=DEV 3=HEX Tab] q=quit +/-=ms"
	if tab == TAB_OVW {
		tabs += " ↑↓=sel ←→=flt"
	}
	right := fmt.Sprintf(" %s | %dms ─┤", time.Now().Format("2006-01-02 15:04"), interval.Milliseconds())
	gap := cols - len(tabs) - len(right) - 2
	if gap < 1 {
		gap = 1
	}
	bar := " " + tabs + strings.Repeat(" ", gap) + right
	if len([]rune(bar)) > cols {
		bar = string([]rune(bar)[:cols])
	}
	// pad
	bar = bar + strings.Repeat(" ", max(0, cols-len([]rune(bar))))

	buf.WriteString(pos(rows-1, 0))
	buf.WriteString(REV)
	buf.WriteString(bar)
	buf.WriteString(RESET)
}

// ── MAIN LOOP ────────────────────────────────────────────────────────────────

var collectIntervalNs atomic.Int64

func collectAll(ss *SysState) {
	cores, load, raplW := readCPU()
	mem := readMem()
	procs, cnts := readProcs()

	ss.mu.Lock()
	ss.Cores = cores
	ss.Load = load
	ss.RaplW = raplW
	ss.Mem = mem
	ss.Procs = procs
	ss.ProcCnts = cnts
	ss.mu.Unlock()
}

func render(ss *SysState, ui *UI, t *Theme) {
	rows, cols := winSize()

	ss.mu.RLock()
	cores := ss.Cores
	load := ss.Load
	raplW := ss.RaplW
	mem := ss.Mem
	procs := make([]ProcStat, len(ss.Procs))
	copy(procs, ss.Procs)
	cnts := ss.ProcCnts
	ss.mu.RUnlock()

	var buf strings.Builder
	buf.WriteString(SYNCON)
	buf.WriteString(HOME)

	switch ui.Tab {
	case TAB_OVW:
		drawOVW(&buf, rows, cols, cores, load, raplW, mem, procs, cnts, ui, t)
	case TAB_DEV:
		drawDEV(&buf, rows, cols, ui, t)
	case TAB_HEX:
		drawHEX(&buf, rows, cols, ui, t)
	}

	buf.WriteString(SYNCOFF)
	os.Stdout.WriteString(buf.String())
}

var filters = []string{"user", "all", "kern", "root"}

func cycleFilter(ui *UI, dir int) {
	for i, f := range filters {
		if f == ui.Filter {
			n := (i + dir + len(filters)) % len(filters)
			ui.Filter = filters[n]
			ui.Sel = 0
			ui.Scroll = 0
			return
		}
	}
}

func sendSignal(ss *SysState, ui *UI, sig syscall.Signal) {
	ss.mu.RLock()
	procs := make([]ProcStat, len(ss.Procs))
	copy(procs, ss.Procs)
	ss.mu.RUnlock()

	visible := filterProcs(procs, ui.Filter)
	if ui.Sel >= 0 && ui.Sel < len(visible) {
		pid := visible[ui.Sel].PID
		syscall.Kill(pid, sig)
	}
}

func handleKey(b byte, inputCh <-chan byte, ui *UI, ss *SysState) bool {
	switch b {
	case 'q', 'Q':
		return true
	case '1':
		ui.Tab = TAB_OVW
	case '2':
		ui.Tab = TAB_DEV
	case '3':
		ui.Tab = TAB_HEX
	case '\t':
		ui.Tab = (ui.Tab + 1) % 3
	case '+', '=':
		ui.Interval += 100 * time.Millisecond
		if ui.Interval > 10*time.Second {
			ui.Interval = 10 * time.Second
		}
		collectIntervalNs.Store(int64(ui.Interval))
	case '-':
		ui.Interval -= 100 * time.Millisecond
		if ui.Interval < 100*time.Millisecond {
			ui.Interval = 100 * time.Millisecond
		}
		collectIntervalNs.Store(int64(ui.Interval))
	case 'c':
		ui.Sort = SORT_CPU
	case 'm':
		ui.Sort = SORT_MEM
	case 'k':
		sendSignal(ss, ui, syscall.SIGTERM)
	case '9':
		sendSignal(ss, ui, syscall.SIGKILL)
	case '\033':
		// read escape sequence: \033[A/B/C/D
		seq := [2]byte{}
		for i := 0; i < 2; i++ {
			select {
			case seq[i] = <-inputCh:
			case <-time.After(50 * time.Millisecond):
				return false
			}
		}
		if seq[0] != '[' {
			return false
		}
		switch seq[1] {
		case 'A': // up
			if ui.Sel > 0 {
				ui.Sel--
			}
		case 'B': // down
			ui.Sel++
		case 'C': // right — next filter
			cycleFilter(ui, +1)
		case 'D': // left — prev filter
			cycleFilter(ui, -1)
		}
	}
	return false
}

func main() {
	truecolor = os.Getenv("COLORTERM") == "truecolor" || os.Getenv("COLORTERM") == "24bit"
	theme := loadTheme()

	rawOn()
	defer rawOff()
	os.Stdout.WriteString(CLRSCR + HOME)

	ss := &SysState{}
	ui := &UI{
		Tab:      TAB_OVW,
		Interval: time.Second,
		Sort:     SORT_CPU,
		Filter:   "user",
	}

	collectIntervalNs.Store(int64(ui.Interval))

	// collector goroutine — runs independently, interval via atomic
	go func() {
		collectAll(ss)
		for {
			time.Sleep(time.Duration(collectIntervalNs.Load()))
			collectAll(ss)
		}
	}()

	// input reader goroutine
	inputCh := make(chan byte, 64)
	go func() {
		buf := make([]byte, 32)
		for {
			n, _ := os.Stdin.Read(buf)
			for i := 0; i < n; i++ {
				inputCh <- buf[i]
			}
		}
	}()

	frameTick := time.NewTicker(FRAME)
	defer frameTick.Stop()

	// initial render after short wait for first collect
	time.Sleep(50 * time.Millisecond)
	render(ss, ui, &theme)

	for {
		select {
		case b := <-inputCh:
			if handleKey(b, inputCh, ui, ss) {
				return
			}
			render(ss, ui, &theme)
		case <-frameTick.C:
			render(ss, ui, &theme)
		}
	}
}
