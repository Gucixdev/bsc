package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// ── MAIN LOOP ────────────────────────────────────────────────────────────────

var collectIntervalNs atomic.Int64

var (
	lastAudioT time.Time
	lastVMT    time.Time
	lastHookT  time.Time
	prevPIDs   map[int]ProcStat  // for ghost detection; updated each collect
	cpuSmooth  map[int]float64   // EMA of CPU per PID; α=0.5 per tick
)

func collectAll(ss *SysState) {
	cores, load, raplW := readCPU()
	mem := readMem()
	procs, cnts := readProcs()
	gpu := readGPU()
	disks := readDisks()
	nets, gw := readNet()
	usb := readUSB()
	batt := readBattery()
	uptime := readUptime()

	var audio []AudioServer
	if time.Since(lastAudioT) >= AUDIO_TTL {
		audio = readAudio()
		lastAudioT = time.Now()
	}

	var (
		vms    VMStat
		gotVMs bool
	)
	if time.Since(lastVMT) >= VM_TTL {
		vms = readVMs()
		lastVMT = time.Now()
		gotVMs = true
	}

	var hooks []string
	if time.Since(lastHookT) >= HOOK_TTL {
		hooks = readHooks()
		lastHookT = time.Now()
	}

	// smooth CPU values: EMA α=0.5 so sort order stabilises over ~2 ticks
	if cpuSmooth == nil {
		cpuSmooth = make(map[int]float64, len(procs))
	}
	for i := range procs {
		pid := procs[i].PID
		procs[i].SmoothCPU = 0.5*procs[i].CPU + 0.5*cpuSmooth[pid]
		cpuSmooth[pid] = procs[i].SmoothCPU
	}

	// ghost tracking: diff old PIDs against new procs
	now := time.Now()
	newPIDs := make(map[int]bool, len(procs))
	for _, p := range procs {
		newPIDs[p.PID] = true
	}

	ss.mu.Lock()
	if ss.Ghosts == nil {
		ss.Ghosts = map[int]GhostProc{}
	}
	// newly dead → become ghosts
	for pid, ps := range prevPIDs {
		if !newPIDs[pid] {
			if _, alreadyGhost := ss.Ghosts[pid]; !alreadyGhost {
				ss.Ghosts[pid] = GhostProc{ps, now}
			}
		}
	}
	// expire old ghosts; revive if PID came back
	for pid := range ss.Ghosts {
		if newPIDs[pid] || time.Since(ss.Ghosts[pid].DiedAt) > GHOST_TTL {
			delete(ss.Ghosts, pid)
		}
	}
	// update prev snapshot
	prevPIDs = make(map[int]ProcStat, len(procs))
	for _, p := range procs {
		prevPIDs[p.PID] = p
	}

	ss.Cores = cores
	ss.Load = load
	ss.RaplW = raplW
	ss.Mem = mem
	ss.Procs = procs
	ss.ProcCnts = cnts
	ss.GPU = gpu
	ss.Nets = nets
	ss.Gateway = gw
	ss.USB = usb
	ss.Battery = batt
	ss.Uptime = uptime
	ss.IRQs = readIRQs()

	var fixed, rem []DiskStat
	for _, d := range disks {
		if d.Removable {
			rem = append(rem, d)
		} else {
			fixed = append(fixed, d)
		}
	}
	ss.Disks = fixed
	ss.Removable = rem

	if audio != nil {
		ss.Audio = audio
	}
	if gotVMs {
		ss.VMs = vms
	}
	if hooks != nil {
		ss.Hooks = hooks
	}
	ss.mu.Unlock()
}

func render(ss *SysState, ui *UI, t *Theme) {
	rows, cols := winSize()

	ss.mu.RLock()
	cores := ss.Cores
	load := ss.Load
	raplW := ss.RaplW
	mem := ss.Mem
	gpu := ss.GPU
	disks := make([]DiskStat, len(ss.Disks))
	copy(disks, ss.Disks)
	nets := make([]NetIface, len(ss.Nets))
	copy(nets, ss.Nets)
	gateway := ss.Gateway
	audio := ss.Audio
	usb := ss.USB
	vms := ss.VMs
	procs := make([]ProcStat, len(ss.Procs))
	copy(procs, ss.Procs)
	cnts := ss.ProcCnts
	ss.mu.RUnlock()

	var buf strings.Builder
	buf.WriteString(SYNCON)
	buf.WriteString(HOME)

	switch ui.Tab {
	case TAB_OVW:
		drawOVW(&buf, rows, cols, cores, load, raplW, mem, gpu, disks, nets, gateway, audio, usb, vms, procs, cnts, ui, t, ss)
	case TAB_DEV:
		drawDEV(&buf, rows, cols, ss, ui, t)
	case TAB_HEX:
		drawHEX(&buf, rows, cols, ss, ui, t)
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
	if ui.SelPID != 0 {
		syscall.Kill(ui.SelPID, sig)
	}
}

func handleKey(b byte, inputCh <-chan byte, ui *UI, ss *SysState) bool {
	// hex search mode eats printable chars
	if ui.Tab == TAB_HEX && ui.HexSearchMode {
		switch b {
		case '\033':
			ui.HexSearchMode = false
		case '\r', '\n':
			ui.HexSearchMode = false
		case '\x08', 127:
			trimmed := strings.TrimRight(ui.HexSearch, " ")
			idx := strings.LastIndex(trimmed, " ")
			if idx >= 0 {
				ui.HexSearch = trimmed[:idx+1]
			} else {
				ui.HexSearch = ""
			}
		default:
			if b >= 0x20 && b < 0x7f {
				ui.HexSearch += string(b)
			}
		}
		return false
	}
	// OVW search mode eats printable chars
	if ui.Tab == TAB_OVW && ui.SearchMode {
		switch b {
		case '\033':
			ui.SearchMode = false
			ui.Search = ""
		case '\r', '\n':
			ui.SearchMode = false
		case '\x08', 127:
			if len(ui.Search) > 0 {
				runes := []rune(ui.Search)
				ui.Search = string(runes[:len(runes)-1])
			}
		default:
			if b >= 0x20 && b < 0x7f {
				ui.Search += string(b)
			}
		}
		return false
	}

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
	case 'R':
		toggleRecording(ui)
	case 'c':
		if ui.Tab == TAB_OVW {
			ui.Sort = SORT_CPU
			ui.Sel = 0
			ui.Scroll = 0
		}
	case 'w':
		if ui.Tab == TAB_HEX {
			ui.HexSource = (ui.HexSource + 1) % 3
			ui.HexScroll = 0
			ui.HexRegScroll = 0
		}
	case 'm':
		if ui.Tab == TAB_OVW {
			ui.Sort = SORT_MEM
			ui.Sel = 0
			ui.Scroll = 0
		}
	case 'd':
		if ui.Tab == TAB_OVW {
			ui.Tab = TAB_DEV
		}
	case 'p':
		if ui.Tab == TAB_HEX {
			ss.mu.RLock()
			if len(ss.Procs) > 0 {
				ui.HexPID = ss.Procs[0].PID
			}
			ss.mu.RUnlock()
			ui.HexScroll = 0
		}
	case 'l':
		if ui.Tab == TAB_HEX {
			ui.NetLock = !ui.NetLock
		} else if ui.Tab == TAB_DEV {
			ui.CoreOffset++
		}
	case 'h':
		if ui.Tab == TAB_HEX && ui.HexSource == HEX_MEM {
			regions := parseMaps(ui.HexPID)
			for i, r := range regions {
				if r.Name == "[heap]" {
					ui.HexRegion = i
					ui.HexScroll = 0
					break
				}
			}
		} else if ui.Tab == TAB_DEV {
			if ui.CoreOffset > 0 {
				ui.CoreOffset--
			}
		}
	case 's':
		if ui.Tab == TAB_HEX && ui.HexSource == HEX_MEM {
			regions := parseMaps(ui.HexPID)
			for i, r := range regions {
				if r.Name == "[stack]" {
					ui.HexRegion = i
					ui.HexScroll = 0
					break
				}
			}
		}
	case 't':
		if ui.Tab == TAB_HEX && ui.HexSource == HEX_MEM {
			regions := parseMaps(ui.HexPID)
			for i, r := range regions {
				if strings.Contains(r.Perms, "x") && r.Name == "" {
					ui.HexRegion = i
					ui.HexScroll = 0
					break
				}
			}
		}
	case '/':
		if ui.Tab == TAB_HEX {
			ui.HexSearch = ""
			ui.HexSearchMode = true
		} else if ui.Tab == TAB_OVW {
			ui.Search = ""
			ui.SearchMode = true
		}
	case ' ':
		if ui.Tab == TAB_OVW && ui.SelPID != 0 {
			if ui.Marked == nil {
				ui.Marked = map[int]bool{}
			}
			ui.Marked[ui.SelPID] = !ui.Marked[ui.SelPID]
		}
	case 'v', '\r', '\n':
		if ui.Tab == TAB_OVW && ui.SelPID != 0 {
			pid := ui.SelPID
			if ui.Detail && ui.DetailPID == pid {
				ui.Detail = false
			} else {
				ui.Detail = true
				ui.DetailPID = pid
				ui.DetailTab = 0
				ui.DetailScroll = 0
			}
		}
	case 'i':
		switch ui.Tab {
		case TAB_OVW:
			if ui.NetScroll > 0 {
				ui.NetScroll--
			}
		case TAB_DEV:
			if ui.DevScroll > 0 {
				ui.DevScroll--
			}
		}
	case 'o':
		switch ui.Tab {
		case TAB_OVW:
			ui.NetScroll++
		case TAB_DEV:
			ui.DevScroll++
		}
	case 'y':
		if ui.Tab == TAB_OVW && ui.SelPID != 0 {
			clipCopy(fmt.Sprintf("%d", ui.SelPID))
		}
	case 'Y':
		if ui.Tab == TAB_OVW && ui.SelPID != 0 {
			ss.mu.RLock()
			for _, p := range ss.Procs {
				if p.PID == ui.SelPID {
					clipCopy(p.Cmd)
					break
				}
			}
			ss.mu.RUnlock()
		}
	case 'f':
		if ui.Tab == TAB_OVW {
			ui.Frozen = !ui.Frozen
		}
	case 'k':
		if ui.Tab == TAB_OVW {
			sendSignal(ss, ui, syscall.SIGKILL)
		}
	case '9':
		sendSignal(ss, ui, syscall.SIGKILL)
	case '\033':
		seq := readEscSeq(inputCh, ui)
		handleEscSeq(seq, inputCh, ui, ss)
	}
	return false
}

func readEscSeq(inputCh <-chan byte, ui *UI) []byte {
	seq := make([]byte, 0, 6)
	for {
		select {
		case b := <-inputCh:
			seq = append(seq, b)
			// terminal: bare ESC, CSI (ESC[...), SS3 (ESCO...)
			if len(seq) == 1 && b != '[' && b != 'O' {
				return seq // bare ESC or other
			}
			// CSI: ends on letter or '~'
			if len(seq) > 1 && (b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b == '~') {
				return seq
			}
			if len(seq) > 8 {
				return seq
			}
		case <-time.After(50 * time.Millisecond):
			if len(seq) == 0 {
				// bare ESC
				if ui.Tab == TAB_OVW && ui.Detail {
					ui.Detail = false
				}
			}
			return seq
		}
	}
}

func handleEscSeq(seq []byte, inputCh <-chan byte, ui *UI, ss *SysState) {
	if len(seq) == 0 {
		return
	}
	// Shift+Tab = ESC [ Z
	if len(seq) == 2 && seq[0] == '[' && seq[1] == 'Z' {
		ui.Tab = (ui.Tab + 2) % 3 // prev tab
		return
	}
	if len(seq) < 2 || seq[0] != '[' {
		return
	}
	switch {
	case seq[1] == 'A': // up arrow
		switch ui.Tab {
		case TAB_OVW:
			ui.SelDelta--
		case TAB_HEX:
			if ui.HexScroll > 0 {
				ui.HexScroll--
			}
		case TAB_DEV:
			if ui.DevScroll > 0 {
				ui.DevScroll--
			}
		}
	case seq[1] == 'B': // down arrow
		switch ui.Tab {
		case TAB_OVW:
			ui.SelDelta++
		case TAB_HEX:
			ui.HexScroll++
		case TAB_DEV:
			ui.DevScroll++
		}
	// Shift+Up / Shift+Down — fast scroll (×5)
	case len(seq) == 5 && seq[1] == '1' && seq[2] == ';' && seq[3] == '2' && seq[4] == 'A':
		switch ui.Tab {
		case TAB_OVW:
			ui.SelDelta -= 5
		case TAB_HEX:
			if ui.HexScroll > 5 { ui.HexScroll -= 5 } else { ui.HexScroll = 0 }
		case TAB_DEV:
			if ui.DevScroll > 5 { ui.DevScroll -= 5 } else { ui.DevScroll = 0 }
		}
	case len(seq) == 5 && seq[1] == '1' && seq[2] == ';' && seq[3] == '2' && seq[4] == 'B':
		switch ui.Tab {
		case TAB_OVW:
			ui.SelDelta += 5
		case TAB_HEX:
			ui.HexScroll += 5
		case TAB_DEV:
			ui.DevScroll += 5
		}
	case seq[1] == 'C': // right arrow
		switch ui.Tab {
		case TAB_OVW:
			cycleFilter(ui, +1)
		case TAB_HEX:
			switch ui.HexSource {
			case HEX_MEM:
				ui.HexRegion++
			default:
				ui.HexSel++
			}
			ui.HexScroll = 0
		case TAB_DEV:
			ui.CoreOffset++
		}
	case seq[1] == 'D': // left arrow
		switch ui.Tab {
		case TAB_OVW:
			cycleFilter(ui, -1)
		case TAB_HEX:
			switch ui.HexSource {
			case HEX_MEM:
				if ui.HexRegion > 0 {
					ui.HexRegion--
				}
			default:
				if ui.HexSel > 0 {
					ui.HexSel--
				}
			}
			ui.HexScroll = 0
		case TAB_DEV:
			if ui.CoreOffset > 0 {
				ui.CoreOffset--
			}
		}
	case len(seq) >= 3 && seq[1] == '5' && seq[2] == '~': // PageUp
		switch ui.Tab {
		case TAB_OVW:
			ui.SelDelta -= 10
		case TAB_HEX:
			if ui.HexScroll > 10 {
				ui.HexScroll -= 10
			} else {
				ui.HexScroll = 0
			}
		case TAB_DEV:
			if ui.DevScroll > 10 {
				ui.DevScroll -= 10
			} else {
				ui.DevScroll = 0
			}
		}
	case len(seq) >= 3 && seq[1] == '6' && seq[2] == '~': // PageDown
		switch ui.Tab {
		case TAB_OVW:
			ui.SelDelta += 10
		case TAB_HEX:
			ui.HexScroll += 10
		case TAB_DEV:
			ui.DevScroll += 10
		}
	}
}

func clipCopy(s string) {
	// pipe text to xclip/xsel via stdin — best effort
	for _, args := range [][]string{
		{"xclip", "-selection", "clipboard"},
		{"xsel", "--clipboard", "--input"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		cmd.Stdin = strings.NewReader(s)
		err := cmd.Run()
		cancel()
		if err == nil {
			return
		}
	}
}


func main() {
	tc := os.Getenv("COLORTERM")
	term := os.Getenv("TERM")
	truecolor = tc == "truecolor" || tc == "24bit" ||
		term == "st-256color" || term == "st" ||
		strings.HasSuffix(term, "-direct") ||
		strings.Contains(os.Getenv("TERM_PROGRAM"), "iTerm")
	theme := loadTheme()

	rawOn()
	defer rawOff()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		rawOff()
		os.Exit(0)
	}()

	os.Stdout.WriteString(CLRSCR + HOME)

	ss := &SysState{}
	ui := &UI{
		Tab:      TAB_OVW,
		Interval: time.Second,
		Sort:     SORT_CPU,
		Filter:   "user",
		NetLock:  true,
	}

	collectIntervalNs.Store(int64(ui.Interval))

	startTrace(ss)

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
