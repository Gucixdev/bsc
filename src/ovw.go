package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var procPos = map[int]float64{}
var ghostFade = map[int]int{}
var stickyColW [8]int
var stickyTermCols int

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

type ColLine struct {
	Text  string
	C     Color
	Dim   bool
	Bold  bool
	Pre   bool   // text already contains ANSI codes; skip attr prefix, use visualLen
	Title string // section name for box header (used when Bold=true in SEC/OPT)
}

func addLine(lines *[]ColLine, h int, text string, c Color, dim, bold bool) {
	if len(*lines) < h {
		*lines = append(*lines, ColLine{Text: text, C: c, Dim: dim, Bold: bold})
	}
}

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

const sparkChars = "▁▂▃▄▅▆▇█"

func sparkline(vals []float64) string {
	if len(vals) == 0 {
		return ""
	}
	if len(vals) > 16 {
		vals = vals[len(vals)-16:]
	}
	max := 0.0
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	runes := []rune(sparkChars) // 8 chars, index 0–7
	var b strings.Builder
	for _, v := range vals {
		idx := 0
		if max > 0 {
			idx = int(v/max*7.0 + 0.5)
		}
		if idx > 7 {
			idx = 7
		}
		b.WriteRune(runes[idx])
	}
	return b.String()
}

func colCPU(cores []CoreStat, load [3]float64, raplW float64, histCPU []float64, histCores [][]float64, h int, t *Theme) []ColLine {
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
	add(sparkline(histCPU), cpuC, true, false)
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
		spark := ""
		if i < len(histCores) && len(histCores[i]) > 0 {
			h5 := histCores[i]
			if len(h5) > 5 {
				h5 = h5[len(h5)-5:]
			}
			spark = " " + sparkline(h5)
		}
		add(fmt.Sprintf("%2d %3.0f%% | %s | %s", i, c.Pct, freqS, tempS)+spark, pctColor(c.Pct, t), false, false)
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

func colRAMGPU(mem MemStat, gpu GPUStat, histGPU, histVRAM []float64, h int, t *Theme) []ColLine {
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
	if gpu.VRAMTot > 0 {
		mrow("VRM", int(gpu.VRAMUsed>>10), int(gpu.VRAMTot>>10), false)
		add(sparkline(histVRAM), pctColor(float64(pct2(int(gpu.VRAMUsed>>10), int(gpu.VRAMTot>>10))), t), true, false)
	}

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
		add(sparkline(histGPU), t.GPU, true, false)
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
			add(sparkline(histGPU), t.GPU, true, false)
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

func colDisk(disks []DiskStat, histDiskR, histDiskW map[string][]float64, h int, t *Theme) []ColLine {
	var lines []ColLine
	add := func(text string, c Color, dim, bold bool) {
		addLine(&lines, h, text, c, dim, bold)
	}
	add("", t.DISK, true, false)
	add("", t.DISK, true, false)
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
		add(sparkline(histDiskR[d.Dev])+" "+sparkline(histDiskW[d.Dev]), t.DISK, true, false)
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

func colNet(nets []NetIface, gateway string, histNetRx, histNetTx map[string][]float64, h int, t *Theme, anon bool) []ColLine {
	var lines []ColLine
	add := func(text string, c Color, dim, bold bool) {
		addLine(&lines, h, text, c, dim, bold)
	}

	hn := ""
	if data, err := os.ReadFile("/etc/hostname"); err == nil {
		hn = strings.TrimSpace(string(data))
	}
	gw := gateway
	if gw == "" {
		gw = "--"
	}
	add(fmt.Sprintf("host:%-12s gw:%s", mHost(hn, anon), mIP(gw, anon)), t.DISK, false, false)

	tcp, udp, unix := connCounts()
	add(fmt.Sprintf("tcp:%-4d udp:%-4d unix:%d", tcp, udp, unix), t.DISK, true, false)

	var dnsServers []string
	if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "nameserver") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					dnsServers = append(dnsServers, mIP(fields[1], anon))
				}
			}
		}
	}
	if len(dnsServers) > 0 {
		add("dns:"+strings.Join(dnsServers[:min(3, len(dnsServers))], " "), t.DISK, true, false)
	}

	vpnPfx := []string{"tun", "tap", "wg", "vpn", "ppp"}
	var vpnNames []string
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
				vpnNames = append(vpnNames, n.Name+"("+mIP(ip, anon)+")")
				break
			}
		}
	}
	if len(vpnNames) > 0 {
		add("VPN: "+strings.Join(vpnNames, " "), t.DISK, false, false)
	}

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
		add(fmt.Sprintf("%-10s %s %s  %s/%d", n.Name, itype, upS, mIP(ip, anon), n.Prefix),
			t.DISK, !n.Up, false)
		if n.Up {
			add(fmt.Sprintf("  tx%5s/s  rx%5s/s", fmtBps(n.TxBps), fmtBps(n.RxBps)),
				t.DISK, false, false)
			add(sparkline(histNetTx[n.Name])+" "+sparkline(histNetRx[n.Name]), t.DISK, true, false)
		}
		if n.MAC != "" {
			add("  mac:"+mMAC(n.MAC, anon), t.DISK, true, false)
		}
		if n.SSID != "" {
			sig := ""
			if n.Signal != 0 && !anon {
				sig = fmt.Sprintf("  %ddBm", n.Signal)
			}
			add("  SSID: "+mStr(n.SSID, anon)+sig, t.DISK, !n.Up, false)
		}
	}

	btEntries, _ := os.ReadDir("/sys/class/bluetooth")
	if len(btEntries) > 0 {
		var btNames []string
		for _, e := range btEntries {
			btNames = append(btNames, e.Name())
		}
		add("Bluetooth: "+strings.Join(btNames, " "), t.DISK, true, false)
	} else {
		add("Bluetooth N/A", t.WARN, false, false)
	}

	return lines
}

func colAudioUSB(audio []AudioServer, usb []string, removable []DiskStat, histDiskR, histDiskW map[string][]float64, h int, t *Theme) []ColLine {
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
		add(sparkline(histDiskR[d.Dev])+" "+sparkline(histDiskW[d.Dev]), t.DISK, true, false)
	}
	return lines
}

func colVMs(vms VMStat, histVMsRun, histQEMURun, histVBoxRun, histVMwRun, histDockRun, histPodRun []float64, h int, t *Theme) []ColLine {
	var lines []ColLine
	add := func(text string, c Color, dim, bold bool) {
		addLine(&lines, h, text, c, dim, bold)
	}

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
		hist    []float64
	}
	sections := []vmSection{
		{"QEMU",       vms.QEMUVMs,   vms.QEMUInst,   true,  histQEMURun},
		{"VirtualBox", vms.VBoxVMs,   vms.VBoxInst,   false, histVBoxRun},
		{"VMware",     vms.VMwareVMs, vms.VMwareInst, false, histVMwRun},
		{"Docker",     vms.DockerVMs, vms.DockerInst, false, histDockRun},
		{"Podman",     vms.PodmanVMs, vms.PodmanInst, false, histPodRun},
	}
	for _, sec := range sections {
		if len(lines) >= h {
			break
		}
		if len(sec.items) == 0 {
			if sec.inst {
				add(sec.label+": 0  "+sparkline(sec.hist), t.DISK, true, false)
			} else {
				add(sec.label+" N/A", t.WARN, false, false)
			}
			continue
		}
		runN := 0
		for _, vm := range sec.items {
			if vm.Status == "run" || vm.Status == "running" {
				runN++
			}
		}
		add(fmt.Sprintf("%s: %d/%d  %s", sec.label, runN, len(sec.items), sparkline(sec.hist)), t.DISK, false, false)
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

	if len(lines) < h {
		if vms.BwrapInst {
			add(fmt.Sprintf("Bubblewrap: %d", vms.BwrapCount), t.DISK, vms.BwrapCount == 0, false)
		} else {
			add("Bubblewrap N/A", t.WARN, false, false)
		}
	}

	if len(lines) < h {
		if vms.Firewall != "" {
			add("Firewall: "+vms.Firewall, t.DISK, false, false)
		} else {
			add("Firewall N/A", t.WARN, false, false)
		}
	}

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

func colCPURAMGPU(cores []CoreStat, load [3]float64, raplW float64, mem MemStat, gpu GPUStat, histCPU, histGPU, histVRAM []float64, histCores [][]float64, h int, t *Theme) []ColLine {
	cpu := colCPU(cores, load, raplW, histCPU, histCores, h, t)
	sep := []ColLine{{}, {}}
	ram := colRAMGPU(mem, gpu, histGPU, histVRAM, h-len(cpu)-len(sep), t)
	return append(append(cpu, sep...), ram...)
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

// drawMemMapBar renders a compact 2-row memory map at 'row': colored bar + labels.
// Reads /proc/meminfo directly.
func drawMemMapBar(buf *strings.Builder, row, cols int, t *Theme) {
	mi := map[string]int64{}
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
			mi[strings.TrimSpace(p[0])] = n
		}
	}
	totKB := mi["MemTotal"]
	if totKB == 0 {
		buf.WriteString(pos(row, 0) + CLEOL)
		buf.WriteString(pos(row+1, 0) + CLEOL)
		return
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
	mapW := max(1, cols)
	widths := make([]int, len(segs))
	for i, s := range segs {
		n := int(s.kb * int64(mapW) / totKB)
		if n < 0 {
			n = 0
		}
		widths[i] = n
	}

	// bar row
	buf.WriteString(pos(row, 0))
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

	// label row
	buf.WriteString(pos(row+1, 0))
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
		buf.WriteString(DIM + ansiCol(s.c) + lbl + RESET)
	}
	buf.WriteString(CLEOL)
}

func drawOVW(buf *strings.Builder, rows, cols int,
	cores []CoreStat, load [3]float64, raplW float64,
	mem MemStat, gpu GPUStat, disks []DiskStat, nets []NetIface, gateway string,
	audio []AudioServer, usb []string, vms VMStat,
	allProcs []ProcStat, cnts map[string]int,
	histCPU, histGPU, histVRAM []float64,
	histNetRx, histNetTx map[string][]float64,
	histDiskR, histDiskW map[string][]float64,
	histVMsRun, histQEMURun, histVBoxRun, histVMwRun, histDockRun, histPodRun []float64,
	histCores [][]float64,
	ui *UI, t *Theme, ss *SysState) {

	topH := rows / 2
	if topH < 10 {
		topH = 10
	}
	if topH > 22 {
		topH = 22
	}

	type section struct {
		name string
		data []ColLine
		minW int
	}
	all := []section{
		{"cpurg",  colCPURAMGPU(cores, load, raplW, mem, gpu, histCPU, histGPU, histVRAM, histCores, topH, t), 28},
		{"disk",   colDisk(disks, histDiskR, histDiskW, topH, t),                                              32},
		{"net",    colNet(nets, gateway, histNetRx, histNetTx, topH, t, ui.Anon),                             44},
		{"audusb", colAudioUSB(audio, usb, ss.Removable, histDiskR, histDiskW, topH, t),                      28},
		{"vms",    colVMs(vms, histVMsRun, histQEMURun, histVBoxRun, histVMwRun, histDockRun, histPodRun, topH, t), 22},
		{"hooks",  colHooks(ss.Hooks, topH, t),                                                                18},
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

	if cols != stickyTermCols {
		stickyColW = [8]int{}
		stickyTermCols = cols
	}

	colWidths := make([]int, n)
	total := 0
	for i, s := range chosen {
		w := s.minW
		for _, line := range s.data {
			if lw := len([]rune(line.Text)) + 1; lw > w {
				w = lw
			}
		}
		if w > stickyColW[i] {
			stickyColW[i] = w
		}
		colWidths[i] = stickyColW[i]
		total += colWidths[i]
	}
	if remainder := cols - total; remainder > 0 {
		for _, expandName := range []string{"hooks", "net", "disk"} {
			for i, s := range chosen {
				if s.name == expandName {
					colWidths[i] += remainder
					remainder = 0
					break
				}
			}
			if remainder == 0 {
				break
			}
		}
	}

	var colData [][]ColLine
	for _, s := range chosen {
		colData = append(colData, s.data)
	}

	renderCols(buf, 0, topH, colData, colWidths, t)

	// compact memory map: 2 rows between top panels and proc list
	drawMemMapBar(buf, topH, cols, t)

	procs := filterProcs(allProcs, ui.Filter)
	if ui.Sort == SORT_MEM {
		sort.Slice(procs, func(i, j int) bool { return procs[i].MemKB > procs[j].MemKB })
	} else {
		sort.Slice(procs, func(i, j int) bool { return procs[i].SmoothCPU > procs[j].SmoothCPU })
	}

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

	buf.WriteString(pos(topH+2, 0))
	buf.WriteString(ansiCol(t.HDR))
	buf.WriteString(BOLD)
	buf.WriteString(hdrLine)
	buf.WriteString(RESET)
	buf.WriteString(CLEOL)

	listStart := topH + 4
	avail := rows - listStart - 2 // hints=rows-2, statusbar=rows-1
	if avail < 0 {
		avail = 0
	}

	type displayProc struct {
		ProcStat
		ghost bool
		sep   bool
	}
	display := make([]displayProc, 0, len(procs))
	for _, p := range procs {
		display = append(display, displayProc{ProcStat: p})
		if ui.Separators[p.PID] {
			display = append(display, displayProc{sep: true})
		}
	}
	type ghostRow struct {
		p      ProcStat
		diedAt time.Time
	}
	var ghostList []ghostRow
	ss.mu.RLock()
	for pid, g := range ss.Ghosts {
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
		cmdW := cols - wPID - wCPU - wMEM - 16
		if cmdW < 0 {
			cmdW = 0
		}
		cmd := p.Cmd
		if ui.Anon && !isKern {
			cmd = "[" + p.Comm + "]"
		}
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

	for i := end - ui.Scroll; i < avail; i++ {
		buf.WriteString(pos(listStart+i, 0))
		buf.WriteString(CLEOL)
	}

	drawHints(buf, rows-2, cols, ui, t)

	drawStatusBar(buf, rows, cols, ui, ui.Interval, ss, t)
}
