package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// procPos — animated fractional row per PID; easing toward SmoothCPU rank
var procPos = map[int]float64{}

// ghostFade — frames since ghost was born (30→0); drives color transition live→blue
var ghostFade = map[int]int{}

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

func colCPU(cores []CoreStat, load [3]float64, raplW float64, h int, t *Theme) []ColLine {
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

	return lines
}

func colRAMGPU(mem MemStat, gpu GPUStat, h int, t *Theme) []ColLine {
	var lines []ColLine
	add := func(text string, c Color, dim, bold bool) {
		addLine(&lines, h, text, c, dim, bold)
	}

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
	mrow("ZRM", mem.ZramUsedKB, mem.ZramTotKB, mem.ZramTotKB == 0)

	// GPU section — always show something
	switch gpu.Source {
	case "nvidia-smi", "nvidia-proc":
		model := gpu.Model
		if len(model) > 24 {
			model = model[:24]
		}
		add(model, t.GPU, false, false)
		fanS := ""
		if gpu.Fan >= 0 {
			fanS = fmt.Sprintf(" fan:%d%%", gpu.Fan)
		}
		add(fmt.Sprintf("util:%3d%% %2dC %.0fW%s", gpu.Util, gpu.TempC, gpu.Power, fanS),
			t.GPU, false, false)
		if gpu.VRAMTot > 0 {
			vu := int(gpu.VRAMUsed >> 20)
			vt := int(gpu.VRAMTot >> 20)
			p := pct2(vu, vt)
			add(fmt.Sprintf("VRAM %s/%s %d%%", fmtMem(vu*1024), fmtMem(vt*1024), p),
				pctColor(float64(p), t), false, false)
		}
		if gpu.Driver != "" {
			add("drv:"+gpu.Driver, t.GPU, true, false)
		}
	case "amdgpu", "rocm", "hwmon", "nouveau", "i915", "xe":
		model := gpu.Model
		if len(model) > 24 {
			model = model[:24]
		}
		add(model, t.GPU, false, false)
		parts := ""
		if gpu.Util > 0 {
			parts += fmt.Sprintf("util:%d%% ", gpu.Util)
		}
		if gpu.TempC > 0 {
			parts += fmt.Sprintf("%dC ", gpu.TempC)
		}
		if gpu.Power > 0 {
			parts += fmt.Sprintf("%.0fW", gpu.Power)
		}
		if parts != "" {
			add(strings.TrimSpace(parts), t.GPU, false, false)
		}
		if gpu.VRAMTot > 0 {
			vu := int(gpu.VRAMUsed >> 20)
			vt := int(gpu.VRAMTot >> 20)
			p := pct2(vu, vt)
			add(fmt.Sprintf("VRAM %s/%s %d%%", fmtMem(vu*1024), fmtMem(vt*1024), p),
				pctColor(float64(p), t), false, false)
		}
		if gpu.Driver != "" {
			add("drv:"+gpu.Driver, t.GPU, true, false)
		}
	default:
		add("GPU: not detected", t.GPU, true, false)
	}

	return lines
}

func fmtBps(bps float64) string {
	switch {
	case bps >= 1e9:
		return fmt.Sprintf("%.1fG", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.1fM", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.0fK", bps/1e3)
	default:
		return fmt.Sprintf("%.0fB", bps)
	}
}

func fmtBytes(b int64) string {
	switch {
	case b >= 1<<40:
		return fmt.Sprintf("%.0fT", float64(b)/(1<<40))
	case b >= 1<<30:
		return fmt.Sprintf("%.0fG", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0fM", float64(b)/(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.0fK", float64(b)/(1<<10))
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func colDisk(disks []DiskStat, h int, t *Theme) []ColLine {
	var lines []ColLine
	add := func(text string, c Color, dim, bold bool) {
		addLine(&lines, h, text, c, dim, bold)
	}
	for di, d := range disks {
		kind := "???"
		if d.Rotary {
			kind = "HDD"
		} else if d.SizeBytes > 0 {
			kind = "SSD"
		}
		sz := ""
		if d.SizeBytes > 0 {
			sz = fmtBytes(d.SizeBytes)
		}
		hdr := d.Dev + "  " + kind
		if sz != "" {
			hdr += " " + sz
		}
		if d.Model != "" {
			m := d.Model
			if len(m) > 16 {
				m = m[:16]
			}
			hdr += "  " + m
		}
		if d.Sched != "" {
			hdr += "  [" + d.Sched + "]"
		}
		add(hdr, t.DISK, false, false)

		idle := d.ReadBps < 1024 && d.WriteBps < 1024 && d.Busy < 1.0
		tempS := "--C"
		if d.TempC > 0 {
			tempS = fmt.Sprintf("%dC", d.TempC)
		}
		add(fmt.Sprintf("  i%s/s o%s/s  busy:%.0f%%  %s",
			fmtBps(d.ReadBps), fmtBps(d.WriteBps), d.Busy, tempS),
			t.DISK, idle, false)
		add(fmt.Sprintf("  R:%.0f W:%.0f iops  Rl:%.1f Wl:%.1fms",
			d.RdIOPS, d.WrIOPS, d.RdLatMs, d.WrLatMs),
			t.DISK, idle, false)
		add(fmt.Sprintf("  total: i%s o%s since boot",
			fmtBytes(d.RdTotal), fmtBytes(d.WrTotal)),
			t.DISK, true, false)

		for i, p := range d.Parts {
			if p.Total == 0 {
				continue
			}
			pct := pct2(int(p.Used>>10), int(p.Total>>10))
			tree := "├"
			if i == len(d.Parts)-1 {
				tree = "└"
			}
			mp := p.Mount
			if len(mp) > 9 {
				// show last 2 path components
				parts := strings.Split(strings.TrimPrefix(mp, "/"), "/")
				if len(parts) >= 2 {
					mp = "/" + strings.Join(parts[len(parts)-2:], "/")
				} else {
					mp = "/" + parts[len(parts)-1]
				}
			}
			fs := p.FS
			if len(fs) > 8 {
				fs = fs[:8]
			}
			dev := p.Dev
			if len(dev) > 8 {
				dev = dev[:8]
			}
			add(fmt.Sprintf(" %s%-8s%-9s%-8s%5s/%-5s %3d%%",
				tree, dev, mp, fs,
				fmtMem(int(p.Used>>10)), fmtMem(int(p.Total>>10)), pct),
				pctColor(float64(pct), t), false, false)
		}
		// blank separator between disks
		if di < len(disks)-1 {
			add("", t.USB, true, false)
		}
	}
	return lines
}

// connCounts — /proc/net/tcp+udp+unix (no external tools)
func connCounts() (tcp, udp, unix int) {
	countLines := func(path string) int {
		data, err := os.ReadFile(path)
		if err != nil {
			return 0
		}
		n := 0
		for _, line := range strings.Split(string(data), "\n") {
			if line != "" && !strings.HasPrefix(strings.TrimSpace(line), "sl") &&
				!strings.HasPrefix(strings.TrimSpace(line), "Num") {
				n++
			}
		}
		return n
	}
	tcp = countLines("/proc/net/tcp") + countLines("/proc/net/tcp6")
	udp = countLines("/proc/net/udp") + countLines("/proc/net/udp6")
	unix = countLines("/proc/net/unix") - 1 // header always present
	if unix < 0 {
		unix = 0
	}
	return
}

func colNet(nets []NetIface, gateway string, h int, t *Theme) []ColLine {
	var lines []ColLine
	add := func(text string, c Color, dim, bold bool) {
		addLine(&lines, h, text, c, dim, bold)
	}

	// hostname + gateway
	hn := ""
	if data, err := os.ReadFile("/etc/hostname"); err == nil {
		hn = strings.TrimSpace(string(data))
	}
	gw := gateway
	if gw == "" {
		gw = "--"
	}
	add(fmt.Sprintf("host:%-12s gw:%s", hn, gw), t.DISK, false, false)

	// connection counts — pure /proc
	tcp, udp, unix := connCounts()
	add(fmt.Sprintf("tcp:%-4d udp:%-4d unix:%d", tcp, udp, unix), t.DISK, true, false)

	// DNS from /etc/resolv.conf
	var dnsServers []string
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "nameserver") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					dnsServers = append(dnsServers, fields[1])
				}
			}
		}
	}
	if len(dnsServers) > 0 {
		add("dns:"+strings.Join(dnsServers[:min(3, len(dnsServers))], " "), t.DISK, true, false)
	}

	// VPN detection from iface names
	var vpnNames []string
	vpnPfx := []string{"tun", "tap", "wg", "vpn", "ppp"}
	for _, n := range nets {
		if !n.Up {
			continue
		}
		for _, p := range vpnPfx {
			if strings.HasPrefix(n.Name, p) {
				ip := n.IP
				if ip == "" {
					ip = "?"
				}
				vpnNames = append(vpnNames, n.Name+"("+ip+")")
				break
			}
		}
	}
	if len(vpnNames) > 0 {
		add("VPN: "+strings.Join(vpnNames, " "), t.DISK, false, false)
	}

	// per-interface
	for _, n := range nets {
		isVPN := false
		for _, p := range vpnPfx {
			if strings.HasPrefix(n.Name, p) {
				isVPN = true
				break
			}
		}
		itype := "LAN"
		if n.SSID != "" {
			itype = "WiFi"
		} else if isVPN {
			itype = "VPN"
		}
		upS := "DOWN"
		if n.Up {
			upS = "UP  "
		}
		ip := n.IP
		if ip == "" {
			ip = "--"
		}
		add(fmt.Sprintf("%-10s %s %s  %s/%d", n.Name, itype, upS, ip, n.Prefix),
			t.DISK, !n.Up, false)
		if n.Up {
			add(fmt.Sprintf("  tx%5s/s  rx%5s/s", fmtBps(n.TxBps), fmtBps(n.RxBps)),
				t.DISK, false, false)
		}
		if n.MAC != "" {
			add("  mac:"+n.MAC, t.DISK, true, false)
		}
		if n.SSID != "" {
			sig := ""
			if n.Signal != 0 {
				sig = fmt.Sprintf("  %ddBm", n.Signal)
			}
			add("  SSID: "+n.SSID+sig, t.DISK, !n.Up, false)
		}
	}

	// Bluetooth — /sys/class/bluetooth/ (no tools)
	btEntries, _ := os.ReadDir("/sys/class/bluetooth")
	if len(btEntries) > 0 {
		var btNames []string
		for _, e := range btEntries {
			btNames = append(btNames, e.Name())
		}
		add("Bluetooth: "+strings.Join(btNames, " "), t.DISK, true, false) // present but passive → dim green
	} else {
		add("Bluetooth N/A", t.WARN, false, false) // no hardware → red
	}

	return lines
}

func colAudioUSB(audio []AudioServer, usb []string, removable []DiskStat, h int, t *Theme) []ColLine {
	var lines []ColLine
	add := func(text string, c Color, dim, bold bool) {
		addLine(&lines, h, text, c, dim, bold)
	}
	for _, a := range audio {
		d := !a.Active
		add(a.Name, t.DISK, d, a.Active)
		for _, l := range a.Lines {
			add("  "+l, t.DISK, true, false)
		}
	}
	// USB devices
	for _, u := range usb {
		add(u, t.DISK, true, false)
	}
	// USB storage drives with stats
	for _, d := range removable {
		kind := "USB-SSD"
		if d.Rotary {
			kind = "USB-HDD"
		}
		if d.Optical {
			kind = "USB-OPT"
		}
		sz := fmtRegSize(d.SizeBytes)
		add(fmt.Sprintf("%s %s %s %s", kind, d.Dev, sz, d.Model), t.DISK, false, false)
		add(fmt.Sprintf("  %5s/s o %5s/s busy:%d%%",
			fmtBps(d.ReadBps), fmtBps(d.WriteBps), int(d.Busy)), t.DISK, true, false)
	}
	return lines
}

func colVMs(vms VMStat, h int, t *Theme) []ColLine {
	var lines []ColLine
	add := func(text string, c Color, dim, bold bool) {
		addLine(&lines, h, text, c, dim, bold)
	}

	// KVM status line
	kvmS := "no /dev/kvm"
	kvmOk := false
	if vms.KVMExists {
		kvmS = vms.KVMVendor
		if kvmS == "" {
			kvmS = "?"
		}
		kvmS += "  ok /dev/kvm"
		kvmOk = true
	}
	if kvmOk {
		add("KVM: "+kvmS, t.DISK, false, false)
	} else {
		add("KVM: "+kvmS, t.WARN, false, false)
	}

	stClr := map[string]Color{
		"run": t.DISK, "running": t.DISK,
		"pause": t.RAM, "stop": t.DISK, "stopped": t.DISK, "new": t.NET,
	}

	type vmSection struct {
		label   string
		items   []VMInfo
		inst    bool
		showRss bool
	}
	sections := []vmSection{
		{"QEMU", vms.QEMUVMs, vms.QEMUInst, true},
		{"VirtualBox", vms.VBoxVMs, vms.VBoxInst, false},
		{"VMware", vms.VMwareVMs, vms.VMwareInst, false},
		{"Docker", vms.DockerVMs, vms.DockerInst, false},
		{"Podman", vms.PodmanVMs, vms.PodmanInst, false},
	}
	for _, sec := range sections {
		if len(lines) >= h {
			break
		}
		if len(sec.items) == 0 {
			if sec.inst {
				add(sec.label+": 0", t.DISK, true, false) // installed, none running → dim green
			} else {
				add(sec.label+" N/A", t.WARN, false, false) // not installed → red
			}
			continue
		}
		runN := 0
		for _, vm := range sec.items {
			if vm.Status == "run" || vm.Status == "running" {
				runN++
			}
		}
		add(fmt.Sprintf("%s: %d/%d", sec.label, runN, len(sec.items)), t.DISK, false, false)
		for i, vm := range sec.items {
			if len(lines) >= h {
				break
			}
			tree := "├"
			if i == len(sec.items)-1 {
				tree = "└"
			}
			clr, ok := stClr[vm.Status]
			if !ok {
				clr = t.DISK
			}
			dim := vm.Status == "stop" || vm.Status == "stopped"
			extra := ""
			if sec.showRss && vm.RssKB > 0 {
				extra = " " + fmtMem(vm.RssKB)
			}
			if vm.RunFor > 0 {
				h2, m2, s2 := vm.RunFor/3600, (vm.RunFor%3600)/60, vm.RunFor%60
				if h2 > 0 {
					extra += fmt.Sprintf(" %dh%02dm", h2, m2)
				} else {
					extra += fmt.Sprintf(" %dm%02ds", m2, s2)
				}
			} else if vm.ID != "" {
				extra += " " + vm.ID
			}
			name := vm.Name
			if len(name) > 14 {
				name = name[:14]
			}
			st := vm.Status
			if len(st) > 3 {
				st = st[:3]
			}
			add(fmt.Sprintf(" %s%-14s[%s]%s", tree, name, st, extra), clr, dim, false)
		}
	}

	// Bubblewrap
	if len(lines) < h {
		if vms.BwrapInst {
			add(fmt.Sprintf("Bubblewrap: %d", vms.BwrapCount), t.DISK, vms.BwrapCount == 0, false)
		} else {
			add("Bubblewrap N/A", t.WARN, false, false)
		}
	}

	// Firewall
	if len(lines) < h {
		if vms.Firewall != "" {
			add("Firewall: "+vms.Firewall, t.DISK, false, false)
		} else {
			add("Firewall N/A", t.WARN, false, false)
		}
	}

	// Sandbox (AppArmor/SELinux)
	if len(lines) < h {
		sb := ""
		if vms.AppArmor {
			sb = "apparmor"
		}
		if vms.SELinux {
			if sb != "" {
				sb += " selinux"
			} else {
				sb = "selinux"
			}
		}
		if sb != "" {
			add("Sandbox: "+sb, t.DISK, false, false)
		} else {
			add("Sandbox N/A", t.WARN, false, false)
		}
	}

	return lines
}

func colCPURAMGPU(cores []CoreStat, load [3]float64, raplW float64, mem MemStat, gpu GPUStat, h int, t *Theme) []ColLine {
	cpu := colCPU(cores, load, raplW, h, t)
	ram := colRAMGPU(mem, gpu, h-len(cpu), t)
	return append(cpu, ram...)
}

func colHooks(hooks []string, h int, t *Theme) []ColLine {
	var lines []ColLine
	add := func(text string, c Color, dim, bold bool) { addLine(&lines, h, text, c, dim, bold) }
	add("HOOKS", t.USB, false, true)
	for _, l := range hooks {
		add("  "+l, t.DISK, false, false)
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
	mem MemStat, gpu GPUStat, disks []DiskStat, nets []NetIface, gateway string,
	audio []AudioServer, usb []string, vms VMStat,
	allProcs []ProcStat, cnts map[string]int,
	ui *UI, t *Theme, ss *SysState) {

	topH := rows / 2
	if topH < 10 {
		topH = 10
	}
	if topH > 22 {
		topH = 22
	}

	// section-based layout: cpurg|disk|net|audusb|vms|hooks
	// min widths: 28|32|44|28|22|18 = 172 total
	type section struct {
		name string
		data []ColLine
		minW int
	}
	all := []section{
		{"cpurg",  colCPURAMGPU(cores, load, raplW, mem, gpu, topH, t), 28},
		{"disk",   colDisk(disks, topH, t),                              32},
		{"net",    colNet(nets, gateway, topH, t),                       44},
		{"audusb", colAudioUSB(audio, usb, ss.Removable, topH, t),        28},
		{"vms",    colVMs(vms, topH, t),                                 22},
		{"hooks",  colHooks(ss.Hooks, topH, t),                          18},
	}
	minTotal := 0
	for _, s := range all {
		minTotal += s.minW
	}

	var chosen []section
	switch {
	case cols >= minTotal:
		chosen = all
	case cols >= minTotal-all[5].minW:
		chosen = all[:5]
	case cols >= minTotal-all[5].minW-all[4].minW:
		chosen = all[:4]
	case cols >= 60:
		chosen = all[:3]
	default:
		chosen = all[:1]
	}

	n := len(chosen)

	// natural width = longest line in column + 1 (separator gap)
	colWidths := make([]int, n)
	for i, s := range chosen {
		w := s.minW
		for _, line := range s.data {
			if lw := len([]rune(line.Text)) + 1; lw > w {
				w = lw
			}
		}
		colWidths[i] = w
	}
	// trim excess from least-important columns first
	total := 0
	for _, w := range colWidths {
		total += w
	}
	for _, trimName := range []string{"hooks", "vms", "audusb", "net", "disk"} {
		if total <= cols {
			break
		}
		for i, s := range chosen {
			if s.name == trimName && total > cols {
				newW := colWidths[i] - (total - cols)
				if newW < s.minW {
					newW = s.minW
				}
				total -= colWidths[i] - newW
				colWidths[i] = newW
			}
		}
	}
	// expand remainder into hooks → net → disk
	remainder := cols - total
	for _, expandName := range []string{"hooks", "net", "disk"} {
		if remainder <= 0 {
			break
		}
		for i, s := range chosen {
			if s.name == expandName && remainder > 0 {
				colWidths[i] += remainder
				remainder = 0
			}
		}
	}

	var colData [][]ColLine
	for _, s := range chosen {
		colData = append(colData, s.data)
	}

	renderCols(buf, 0, topH, colData, colWidths, t)

	// proc section
	procs := filterProcs(allProcs, ui.Filter)

	// sort by EMA-smoothed CPU (or MEM)
	if ui.Sort == SORT_MEM {
		sort.Slice(procs, func(i, j int) bool { return procs[i].MemKB > procs[j].MemKB })
	} else {
		sort.Slice(procs, func(i, j int) bool { return procs[i].SmoothCPU > procs[j].SmoothCPU })
	}

	// easing: procPos drifts toward SmoothCPU rank
	targetRank := make(map[int]int, len(procs))
	for i, p := range procs {
		targetRank[p.PID] = i
		target := float64(i)
		if _, ok := procPos[p.PID]; !ok {
			procPos[p.PID] = target
		}
		if !ui.Frozen {
			procPos[p.PID] += (target - procPos[p.PID]) * 0.08
		}
	}

	// display order follows animated position
	sort.SliceStable(procs, func(i, j int) bool {
		return procPos[procs[i].PID] < procPos[procs[j].PID]
	})


	rn := cnts["R"]
	sn := cnts["S"]
	dn := cnts["D"]
	zn := cnts["Z"]
	stats := fmt.Sprintf("R:%d S:%d D:%d Z:%d", rn, sn, dn, zn)
	filt := fmt.Sprintf("◄ %s ►", ui.Filter)
	sl := strings.ToUpper(ui.Sort)
	if ui.Frozen {
		sl = "FROZEN"
	}
	srch := ""
	if ui.SearchMode {
		srch = " /" + ui.Search + "_"
	} else if ui.Search != "" {
		srch = " /" + ui.Search
	}
	dashN := cols - len(filt) - len(stats) - len(sl) - len(srch) - 14
	if dashN < 0 {
		dashN = 0
	}
	hdrLine := fmt.Sprintf(" PROC [%s]%s%s[%s][%s] ", filt, srch, strings.Repeat("─", dashN), stats, sl)
	if len([]rune(hdrLine)) > cols {
		hdrLine = string([]rune(hdrLine)[:cols])
	}

	buf.WriteString(pos(topH, 0))
	buf.WriteString(ansiCol(t.HDR))
	buf.WriteString(BOLD)
	buf.WriteString(hdrLine)
	buf.WriteString(RESET)
	buf.WriteString(CLEOL)

	listStart := topH + 2
	avail := rows - listStart - 2 // hints=rows-2, statusbar=rows-1
	if avail < 0 {
		avail = 0
	}

	// build combined display list: live procs + ghosts (dead, dim, at bottom)
	type displayProc struct {
		ProcStat
		ghost bool // dead process (TTL ghost at bottom)
		sep   bool // blank separator row (Tab key)
	}
	display := make([]displayProc, 0, len(procs))
	for _, p := range procs {
		display = append(display, displayProc{ProcStat: p})
		if ui.Separators[p.PID] {
			display = append(display, displayProc{sep: true})
		}
	}
	// collect ghosts into sorted slice (most recently dead first)
	type ghostRow struct {
		p      ProcStat
		diedAt time.Time
	}
	var ghostList []ghostRow
	ss.mu.RLock()
	for pid, g := range ss.Ghosts {
		// seed ghostFade for newly seen ghosts (first render after death)
		if _, known := ghostFade[pid]; !known {
			ghostFade[pid] = 30
		}
		p := g.ProcStat
		p.State = "†"
		isKern := p.Cmd == "["+p.Comm+"]"
		skip := false
		switch ui.Filter {
		case "user":
			if p.UID == 0 || isKern {
				skip = true
			}
		case "root":
			if p.UID != 0 {
				skip = true
			}
		case "kern":
			if !isKern {
				skip = true
			}
		}
		if !skip {
			ghostList = append(ghostList, ghostRow{p, g.DiedAt})
		}
	}
	ss.mu.RUnlock()
	// tick ghostFade; remove PIDs that are no longer ghosts
	for pid, f := range ghostFade {
		ss.mu.RLock()
		_, stillGhost := ss.Ghosts[pid]
		ss.mu.RUnlock()
		if !stillGhost {
			delete(ghostFade, pid)
		} else if f > 0 {
			ghostFade[pid] = f - 1
		}
	}
	sort.Slice(ghostList, func(i, j int) bool {
		return ghostList[i].diedAt.After(ghostList[j].diedAt)
	})
	for _, gr := range ghostList {
		display = append(display, displayProc{ProcStat: gr.p, ghost: true})
	}

	// re-anchor cursor PID after list is finalized
	if ui.SelPID > 0 {
		for i, dp := range display {
			if dp.PID == ui.SelPID {
				ui.Sel = i
				break
			}
		}
	}
	ui.Sel += ui.SelDelta
	ui.SelDelta = 0
	if ui.Sel >= 0 && ui.Sel < len(display) {
		ui.SelPID = display[ui.Sel].PID
	}

	// clamp scroll + sel
	if ui.Scroll < 0 {
		ui.Scroll = 0
	}
	if len(display) > avail && ui.Scroll > len(display)-avail {
		ui.Scroll = len(display) - avail
	}
	if ui.Sel < 0 {
		ui.Sel = 0
	}
	if ui.Sel >= len(display) && len(display) > 0 {
		ui.Sel = len(display) - 1
	}
	// auto-scroll to keep sel visible
	if ui.Sel < ui.Scroll {
		ui.Scroll = ui.Sel
	}
	if ui.Sel >= ui.Scroll+avail {
		ui.Scroll = ui.Sel - avail + 1
	}

	end := ui.Scroll + avail
	if end > len(display) {
		end = len(display)
	}

	// measure column widths from visible rows
	wPID, wCPU, wMEM := len("PID"), len("CPU%"), len("MEM")
	for _, dp := range display[ui.Scroll:end] {
		if dp.sep { continue }
		if w := len(fmt.Sprintf("%d", dp.PID)); w > wPID { wPID = w }
		cpu := fmt.Sprintf("%.1f", dp.CPU)
		if dp.ghost { cpu = "--" }
		if w := len(cpu); w > wCPU { wCPU = w }
		if w := len(fmtMem(dp.MemKB)); w > wMEM { wMEM = w }
	}
	ui_ := DIM + ansiCol(t.USB) + "│" + RESET // separator shorthand

	// header
	hdrLine2 := fmt.Sprintf("   %-*s %s %-*s %s %-*s %s T %s CMD",
		wPID, "PID", ui_, wCPU, "CPU%", ui_, wMEM, "MEM", ui_, ui_)
	buf.WriteString(pos(topH+1, 0))
	buf.WriteString(DIM + clampVisual(hdrLine2, cols) + RESET + CLEOL)

	for i, dp := range display[ui.Scroll:end] {
		absI := ui.Scroll + i
		buf.WriteString(pos(listStart+i, 0))
		if dp.sep {
			buf.WriteString(DIM + ansiCol(t.USB) + strings.Repeat("─", cols) + RESET)
			continue
		}
		isSel := absI == ui.Sel
		p := dp.ProcStat

		isKern := p.Comm != "" && p.Cmd == "["+p.Comm+"]"
		isMarked := ui.Marked != nil && ui.Marked[p.PID]
		var attr string
		switch {
		case isSel:
			attr = bgRGB(t.CPU[0], t.CPU[1], t.CPU[2]) + fgRGB(0, 0, 0) + BOLD
		case dp.ghost:
			if fade := ghostFade[p.PID]; fade > 0 {
				ratio := float64(fade) / 30.0
				r := uint8(float64(t.CPU[0])*ratio + float64(t.NET[0])*(1-ratio))
				g := uint8(float64(t.CPU[1])*ratio + float64(t.NET[1])*(1-ratio))
				b := uint8(float64(t.CPU[2])*ratio + float64(t.NET[2])*(1-ratio))
				attr = fgRGB(r, g, b)
			} else {
				attr = DIM + ansiCol(t.NET)
			}
		case isMarked:
			attr = ansiCol(t.MARK) + BOLD
		case p.State == "Z":
			attr = ansiCol(t.WARN) + BOLD
		case isKern:
			attr = DIM + ansiCol(t.USB)
		case p.CPU >= 20:
			attr = ansiCol(t.WARN)
		case p.CPU >= 5:
			attr = ansiCol(t.RAM)
		default:
			attr = ansiCol(t.DISK)
		}

		moveC := ' '
		if !dp.ghost {
			diff := procPos[p.PID] - float64(targetRank[p.PID])
			if diff < 0 {
				diff = -diff
			}
			if diff > 0.3 {
				moveC = '>'
			}
		}
		markC := ' '
		if ui.Marked != nil && ui.Marked[p.PID] {
			markC = '●'
		}
		cpuStr := fmt.Sprintf("%*.1f", wCPU, p.CPU)
		if dp.ghost {
			cpuStr = fmt.Sprintf("%*s", wCPU, "--")
		}
		// layout per row (all fixed-width): moveC(1)+markC(1)+sp+PID(wPID)+sp │ sp+cpu(wCPU)+sp │ sp+mem(wMEM)+sp │ sp+T+sp │ sp+cmd
		cmdW := cols - wPID - wCPU - wMEM - 16
		if cmdW < 0 {
			cmdW = 0
		}
		cmd := p.Cmd
		if len([]rune(cmd)) > cmdW {
			cmd = string([]rune(cmd)[:cmdW])
		}

		buf.WriteString(attr)
		buf.WriteString(fmt.Sprintf("%c%c %*d ", moveC, markC, wPID, p.PID))
		buf.WriteString(RESET + DIM + ansiCol(t.USB) + "│" + RESET + attr)
		buf.WriteString(fmt.Sprintf(" %s ", cpuStr))
		buf.WriteString(RESET + DIM + ansiCol(t.USB) + "│" + RESET + attr)
		buf.WriteString(fmt.Sprintf(" %*s ", wMEM, fmtMem(p.MemKB)))
		buf.WriteString(RESET + DIM + ansiCol(t.USB) + "│" + RESET + attr)
		buf.WriteString(fmt.Sprintf(" %s ", p.State))
		buf.WriteString(RESET + DIM + ansiCol(t.USB) + "│" + RESET + attr)
		buf.WriteString(fmt.Sprintf(" %-*s", cmdW, cmd))
		buf.WriteString(RESET)
	}

	// clear remaining rows in proc section
	for i := end - ui.Scroll; i < avail; i++ {
		buf.WriteString(pos(listStart+i, 0))
		buf.WriteString(CLEOL)
	}

	// hints row
	drawHints(buf, rows-2, cols, ui, t)

	drawStatusBar(buf, rows, cols, ui, ui.Interval, ss, t)
}
