package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// readSysctl — reads a single /proc/sys/ value
func readSysctl(key string) string {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	v, err := os.ReadFile(path)
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(v))
}

type secListenPort struct {
	Proto string
	Port  int
}

// readListenPorts — parses /proc/net/tcp and /proc/net/tcp6 for listening sockets
func readListenPorts() []secListenPort {
	var out []secListenPort
	seen := map[int]bool{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		proto := "tcp"
		if strings.Contains(path, "tcp6") {
			proto = "tcp6"
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if i == 0 || line == "" {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != "0A" {
				continue
			}
			parts := strings.SplitN(f[1], ":", 2)
			if len(parts) < 2 {
				continue
			}
			port64, err := strconv.ParseInt(parts[1], 16, 32)
			if err != nil {
				continue
			}
			port := int(port64)
			if seen[port] {
				continue
			}
			seen[port] = true
			out = append(out, secListenPort{Proto: proto, Port: port})
		}
	}
	return out
}

// readLoggedUsers — runs `who`
func readLoggedUsers() []string {
	out := runCmd(2000000000, "who")
	if out == "" {
		return nil
	}
	var users []string
	for _, line := range strings.Split(out, "\n") {
		if line != "" {
			users = append(users, line)
		}
	}
	return users
}

// ── Rootkit detection helpers ─────────────────────────────────────────────────

// countProcPIDs — count numeric entries in /proc (visible processes)
func countProcPIDs() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
			n++
		}
	}
	return n
}

// totalProcsFromLoadavg — /proc/loadavg field 4 = "running/total"
func totalProcsFromLoadavg() int {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return -1
	}
	f := strings.Fields(string(raw))
	if len(f) < 4 {
		return -1
	}
	parts := strings.SplitN(f[3], "/", 2)
	if len(parts) < 2 {
		return -1
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil {
		return -1
	}
	return n
}

// readTaint — parse /proc/sys/kernel/tainted bit flags
func readTaint() (int64, []string) {
	raw := readSysctl("kernel.tainted")
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v == 0 {
		return v, nil
	}
	bits := []struct {
		bit int
		msg string
	}{
		{0, "proprietary module"}, {1, "module force-loaded"}, {2, "kernel oops"},
		{3, "module force-unloaded"}, {4, "SMP unsafe"}, {5, "bad page"},
		{6, "user request"}, {7, "kernel died"}, {8, "ACPI override"},
		{9, "kernel warning"}, {10, "staging driver"}, {11, "firmware workaround"},
		{12, "externally-built module"}, {13, "unsigned module"}, {14, "soft lockup"},
		{15, "live patch"}, {16, "auxiliary"}, {17, "struct randomization disabled"},
	}
	var msgs []string
	for _, b := range bits {
		if v&(1<<b.bit) != 0 {
			msgs = append(msgs, b.msg)
		}
	}
	return v, msgs
}

// readUnsignedModules — scan /proc/modules for unsigned/OOT modules ("(E)" or "(OE)")
func readUnsignedModules() []string {
	raw, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "(E)") || strings.Contains(line, "(OE)") {
			out = append(out, strings.Fields(line)[0])
		}
	}
	return out
}

// countRawSockets — /proc/net/packet: each non-header line = raw socket
func countRawSockets() int {
	raw, err := os.ReadFile("/proc/net/packet")
	if err != nil {
		return -1
	}
	n := 0
	for i, line := range strings.Split(string(raw), "\n") {
		if i == 0 || line == "" {
			continue
		}
		n++
	}
	return n
}

// checkLdPreload — scan /proc/*/environ for LD_PRELOAD injection
func checkLdPreload() []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	found := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		env, err := os.ReadFile("/proc/" + name + "/environ")
		if err != nil {
			continue
		}
		for _, kv := range strings.Split(string(env), "\x00") {
			if strings.HasPrefix(kv, "LD_PRELOAD=") {
				found[name] = strings.TrimPrefix(kv, "LD_PRELOAD=")
				break
			}
		}
	}
	var out []string
	for pid, val := range found {
		out = append(out, fmt.Sprintf("pid %s → %s", pid, val))
	}
	return out
}

// checkKallsymsLeak — if first address in /proc/kallsyms is non-zero, pointers are exposed
func checkKallsymsLeak() bool {
	raw, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		return f[0] != "0000000000000000" && f[0] != "0"
	}
	return false
}

// countSUIDBinaries — find SUID binaries in common paths
func countSUIDBinaries() int {
	out := runCmd(2000000000, "find", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
		"-perm", "/4000", "-type", "f")
	if out == "" {
		return 0
	}
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if l != "" {
			n++
		}
	}
	return n
}

// hiddenProcDelta — difference between /proc PID count and loadavg total
func hiddenProcDelta() (proc, lavg, delta int) {
	proc = countProcPIDs()
	lavg = totalProcsFromLoadavg()
	if proc < 0 || lavg < 0 {
		return proc, lavg, 0
	}
	delta = lavg - proc
	if delta < 0 {
		delta = 0
	}
	return
}

func countSGIDBinaries() int {
	out := runCmd(2000000000, "find", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
		"-perm", "/2000", "-type", "f")
	if out == "" {
		return 0
	}
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if l != "" {
			n++
		}
	}
	return n
}

func checkGlobalPreload() []string {
	raw, err := os.ReadFile("/etc/ld.so.preload")
	if err != nil || len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

func checkCorePatternPipe() (bool, string) {
	v := readSysctl("kernel.core_pattern")
	if strings.HasPrefix(v, "|") {
		return true, v
	}
	return false, v
}

func checkTmpSticky() bool {
	info, err := os.Stat("/tmp")
	if err != nil {
		return false
	}
	return info.Mode()&01000 != 0
}

func countShellUsers() (total, withLogin int) {
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return 0, 0
	}
	noLogin := map[string]bool{
		"/sbin/nologin": true, "/bin/false": true, "/usr/sbin/nologin": true,
		"/bin/nologin": true, "/usr/bin/nologin": true,
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		total++
		if !noLogin[f[6]] {
			withLogin++
		}
	}
	return
}

type netConn struct {
	Local  string
	Remote string
	State  string
}

func readEstablished() []netConn {
	var out []netConn
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if i == 0 || line == "" {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != "01" { // 01 = ESTABLISHED
				continue
			}
			local := hexAddrToIP(f[1])
			remote := hexAddrToIP(f[2])
			out = append(out, netConn{Local: local, Remote: remote, State: "ESTAB"})
		}
	}
	return out
}

func hexAddrToIP(s string) string {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return s
	}
	ipHex := parts[0]
	portHex := parts[1]
	port, _ := strconv.ParseInt(portHex, 16, 32)
	if len(ipHex) == 8 {
		// IPv4 little-endian
		var b [4]byte
		v, _ := strconv.ParseUint(ipHex, 16, 32)
		b[0] = byte(v)
		b[1] = byte(v >> 8)
		b[2] = byte(v >> 16)
		b[3] = byte(v >> 24)
		return fmt.Sprintf("%d.%d.%d.%d:%d", b[0], b[1], b[2], b[3], port)
	}
	return fmt.Sprintf("%s:%d", ipHex, port)
}

func isPrivateIP(addr string) bool {
	for _, pfx := range []string{
		"127.", "10.", "192.168.", "::1", "0.0.0.0",
	} {
		if strings.HasPrefix(addr, pfx) {
			return true
		}
	}
	// 172.16-31.x.x
	if strings.HasPrefix(addr, "172.") {
		rest := strings.TrimPrefix(addr, "172.")
		dot := strings.IndexByte(rest, '.')
		if dot > 0 {
			n, _ := strconv.Atoi(rest[:dot])
			if n >= 16 && n <= 31 {
				return true
			}
		}
	}
	return false
}

func countUDPListen() int {
	n := 0
	for _, path := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(raw), "\n") {
			if i == 0 || line == "" {
				continue
			}
			n++
		}
	}
	return n
}

func checkSSHAuthKeys() []string {
	var found []string
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 6 {
			continue
		}
		home := f[5]
		ak := home + "/.ssh/authorized_keys"
		if info, err := os.Stat(ak); err == nil && info.Size() > 0 {
			found = append(found, f[0])
		}
	}
	return found
}

func drawSEC(buf *strings.Builder, rows, cols int, ss *SysState, ui *UI, t *Theme) {
	hdr := clampStr(" SEC"+strings.Repeat("─", max(0, cols-4)), cols)
	buf.WriteString(pos(0, 0))
	buf.WriteString(ansiCol(t.HDR) + BOLD + hdr + RESET + CLEOL)

	// collect into virtual buffer then render with scroll
	type vline struct{ s string }
	var vbuf []vline
	add := func(s string) { vbuf = append(vbuf, vline{s}) }
	blank := func() { add("") }

	ok   := ansiCol(t.DISK) + BOLD + "OK  " + RESET
	warn := ansiCol(t.WARN) + BOLD + "WARN" + RESET
	info := DIM + ansiCol(t.USB)
	hc   := ansiCol(t.USB) + BOLD

	boolOK := func(v string, goodVals ...string) string {
		for _, g := range goodVals {
			if v == g {
				return ok
			}
		}
		return warn
	}

	ss.mu.RLock()
	vms := ss.VMs
	ss.mu.RUnlock()

	// ── Kernel hardening ──────────────────────────────────────────────────────
	add(hc + " ── kernel hardening" + RESET)

	aslr := readSysctl("kernel.randomize_va_space")
	aslrSt := warn
	if aslr == "2" { aslrSt = ok } else if aslr == "1" { aslrSt = ansiCol(t.RAM) + BOLD + "PART" + RESET }
	add(fmt.Sprintf("  %s ASLR                   %s%s%s  (%s)", aslrSt, info, aslrDesc(aslr), RESET, aslr))

	kptr := readSysctl("kernel.kptr_restrict")
	kptrSt := warn
	if kptr != "0" { kptrSt = ok }
	add(fmt.Sprintf("  %s kptr_restrict           %s%s%s  (%s)", kptrSt, info, kptrDesc(kptr), RESET, kptr))

	dmesg := readSysctl("kernel.dmesg_restrict")
	dmesgSt := warn
	if dmesg == "1" { dmesgSt = ok }
	add(fmt.Sprintf("  %s dmesg_restrict          %s%s%s  (%s)", dmesgSt, info,
		map[string]string{"0": "readable by all", "1": "root only"}[dmesg], RESET, dmesg))

	perf := readSysctl("kernel.perf_event_paranoid")
	perfSt := ok
	if perf == "-1" || perf == "0" { perfSt = warn }
	add(fmt.Sprintf("  %s perf_event_paranoid     %slevel %s%s", perfSt, info, perf, RESET))

	ptrace := readSysctl("kernel.yama.ptrace_scope")
	ptraceSt := warn
	if ptrace == "1" || ptrace == "2" || ptrace == "3" { ptraceSt = ok }
	add(fmt.Sprintf("  %s ptrace_scope            %s%s%s  (%s)", ptraceSt, info,
		map[string]string{"0": "unrestricted", "1": "parent only", "2": "admin only", "3": "disabled", "?": "Yama n/a"}[ptrace], RESET, ptrace))

	suid := readSysctl("fs.suid_dumpable")
	suidSt := ok
	if suid != "0" { suidSt = warn }
	add(fmt.Sprintf("  %s suid_dumpable           %s%s%s  (%s)", suidSt, info,
		map[string]string{"0": "disabled", "1": "enabled", "2": "suidsafe"}[suid], RESET, suid))

	bpf := readSysctl("kernel.unprivileged_bpf_disabled")
	bpfSt := warn
	if bpf == "1" || bpf == "2" { bpfSt = ok }
	add(fmt.Sprintf("  %s unprivileged_bpf        %s%s%s  (%s)", bpfSt, info,
		map[string]string{"0": "allowed", "1": "disabled", "2": "admin only"}[bpf], RESET, bpf))

	userns := readSysctl("kernel.unprivileged_userns_clone")
	usernsSt := warn
	if userns == "0" || userns == "?" { usernsSt = ok }
	add(fmt.Sprintf("  %s unprivileged_userns     %s%s%s  (%s)", usernsSt, info,
		map[string]string{"0": "disabled", "1": "allowed", "?": "n/a"}[userns], RESET, userns))

	kexec := readSysctl("kernel.kexec_load_disabled")
	kexecSt := warn
	if kexec == "1" { kexecSt = ok }
	add(fmt.Sprintf("  %s kexec_load_disabled     %s%s%s  (%s)", kexecSt, info,
		map[string]string{"0": "kexec allowed", "1": "kexec disabled", "?": "n/a"}[kexec], RESET, kexec))

	symlinks := readSysctl("fs.protected_symlinks")
	hardlinks := readSysctl("fs.protected_hardlinks")
	symlinkSt := warn
	if symlinks == "1" { symlinkSt = ok }
	hlSt := warn
	if hardlinks == "1" { hlSt = ok }
	add(fmt.Sprintf("  %s protected_symlinks      %s%s%s  (%s)", symlinkSt, info,
		map[string]string{"0": "off", "1": "on"}[symlinks], RESET, symlinks))
	add(fmt.Sprintf("  %s protected_hardlinks     %s%s%s  (%s)", hlSt, info,
		map[string]string{"0": "off", "1": "on"}[hardlinks], RESET, hardlinks))

	ipfwd := readSysctl("net.ipv4.ip_forward")
	ipfwdSt := ok
	if ipfwd == "1" { ipfwdSt = warn }
	add(fmt.Sprintf("  %s ip_forward              %s%s%s  (%s)", ipfwdSt, info,
		map[string]string{"0": "off", "1": "ON — routing enabled"}[ipfwd], RESET, ipfwd))

	blank()

	// ── Kernel taint ──────────────────────────────────────────────────────────
	add(hc + " ── kernel taint" + RESET)
	taintVal, taintMsgs := readTaint()
	if taintVal == 0 {
		add(fmt.Sprintf("  %s tainted=0              %sclean%s", ok, info, RESET))
	} else {
		add(fmt.Sprintf("  %s tainted=%-6d", warn, taintVal))
		for _, msg := range taintMsgs {
			add(fmt.Sprintf("          %s! %s%s", ansiCol(t.WARN), msg, RESET))
		}
	}

	blank()

	// ── Rootkit indicators ────────────────────────────────────────────────────
	add(hc + " ── rootkit indicators" + RESET)

	procN, lavgN, delta := hiddenProcDelta()
	hdSt := ok
	hdNote := "no discrepancy"
	if delta > 5 { hdSt = warn; hdNote = fmt.Sprintf("!! %d processes missing from /proc", delta) }
	add(fmt.Sprintf("  %s hidden procs            %s/proc:%d  loadavg_total:%d  Δ:%d  %s%s",
		hdSt, info, procN, lavgN, delta, hdNote, RESET))

	preloads := checkLdPreload()
	plSt := ok
	if len(preloads) > 0 { plSt = warn }
	add(fmt.Sprintf("  %s LD_PRELOAD inject        %s%d processes with LD_PRELOAD%s",
		plSt, info, len(preloads), RESET))
	for _, p := range preloads {
		add(fmt.Sprintf("          %s! %s%s", ansiCol(t.WARN), p, RESET))
	}

	kallLeak := checkKallsymsLeak()
	kallSt := ok
	kallNote := "addresses hidden"
	if kallLeak { kallSt = warn; kallNote = "!! real addresses visible in /proc/kallsyms" }
	add(fmt.Sprintf("  %s kallsyms leak           %s%s%s", kallSt, info, kallNote, RESET))

	rawN := countRawSockets()
	rawSt := ok
	rawNote := fmt.Sprintf("%d raw sockets", rawN)
	if rawN > 2 { rawSt = warn; rawNote += " — check for sniffers" }
	add(fmt.Sprintf("  %s raw sockets             %s%s%s", rawSt, info, rawNote, RESET))

	unsignedMods := readUnsignedModules()
	modSt := ok
	if len(unsignedMods) > 0 { modSt = warn }
	add(fmt.Sprintf("  %s unsigned modules        %s%d unsigned/OOT%s", modSt, info, len(unsignedMods), RESET))
	for _, m := range unsignedMods {
		add(fmt.Sprintf("          %s! %s%s", ansiCol(t.WARN), m, RESET))
	}

	suids := countSUIDBinaries()
	suidCSt := ok
	suidNote := fmt.Sprintf("%d SUID binaries", suids)
	if suids > 30 { suidCSt = warn; suidNote += " — unusually high" }
	add(fmt.Sprintf("  %s SUID binaries           %s%s%s", suidCSt, info, suidNote, RESET))

	globalPre := checkGlobalPreload()
	glSt := ok
	glNote := "clean"
	if len(globalPre) > 0 {
		glSt = warn
		glNote = fmt.Sprintf("%d entries:", len(globalPre))
	}
	add(fmt.Sprintf("  %s /etc/ld.so.preload      %s%s%s", glSt, info, glNote, RESET))
	for _, p := range globalPre {
		add(fmt.Sprintf("          %s! %s%s", ansiCol(t.WARN), p, RESET))
	}

	corePiped, corePattern := checkCorePatternPipe()
	cpSt := ok
	if corePiped {
		cpSt = warn
	}
	add(fmt.Sprintf("  %s core_pattern            %s%s%s", cpSt, info, corePattern, RESET))

	sgids := countSGIDBinaries()
	sgidSt := ok
	sgidNote := fmt.Sprintf("%d SGID binaries", sgids)
	if sgids > 20 {
		sgidSt = warn
		sgidNote += " — unusually high"
	}
	add(fmt.Sprintf("  %s SGID binaries           %s%s%s", sgidSt, info, sgidNote, RESET))

	tmpSt := ok
	tmpNote := "sticky bit set"
	if !checkTmpSticky() {
		tmpSt = warn
		tmpNote = "no sticky bit on /tmp"
	}
	add(fmt.Sprintf("  %s /tmp sticky bit          %s%s%s", tmpSt, info, tmpNote, RESET))

	blank()

	// ── MAC / firewall ────────────────────────────────────────────────────────
	add(hc + " ── MAC / firewall" + RESET)

	aaSt := warn
	if vms.AppArmor { aaSt = ok }
	add(fmt.Sprintf("  %s AppArmor               %s%s%s", aaSt, info, map[bool]string{true: "active", false: "inactive"}[vms.AppArmor], RESET))

	seSt := warn
	if vms.SELinux { seSt = ok }
	add(fmt.Sprintf("  %s SELinux                %s%s%s", seSt, info, map[bool]string{true: "enforcing", false: "inactive"}[vms.SELinux], RESET))

	fwSt := warn
	if vms.Firewall != "" { fwSt = ok }
	fw := vms.Firewall
	if fw == "" { fw = "none detected" }
	add(fmt.Sprintf("  %s Firewall               %s%s%s", fwSt, info, fw, RESET))

	swapEnc := "?"
	if raw, err := os.ReadFile("/proc/swaps"); err == nil {
		if strings.Contains(string(raw), "dm-") || strings.Contains(string(raw), "zram") {
			swapEnc = "zram/encrypted"
		} else if strings.Count(string(raw), "\n") > 1 {
			swapEnc = "plain"
		} else {
			swapEnc = "none"
		}
	}
	swapEncSt := ok
	if swapEnc == "plain" { swapEncSt = warn }
	add(fmt.Sprintf("  %s Swap                   %s%s%s", swapEncSt, info, swapEnc, RESET))

	blank()

	// ── Listening ports ───────────────────────────────────────────────────────
	add(hc + " ── listening ports" + RESET)
	ports := readListenPorts()
	if len(ports) == 0 {
		add(info + "  (none)" + RESET)
	} else {
		line := "  "
		for i, p := range ports {
			if i > 0 { line += "  " }
			if len(line) > cols-12 { add(line); line = "  " }
			line += fmt.Sprintf("%s%s:%d%s", ansiCol(t.NET), p.Proto, p.Port, RESET)
		}
		if line != "  " { add(line) }
	}

	blank()

	// ── network security ──────────────────────────────────────────────────────
	add(hc + " ── network security" + RESET)

	syncook := readSysctl("net.ipv4.tcp_syncookies")
	add(fmt.Sprintf("  %s tcp_syncookies          %s%s%s  (%s)", boolOK(syncook, "1"), info,
		map[string]string{"0": "disabled", "1": "SYN flood protection"}[syncook], RESET, syncook))

	rpfall := readSysctl("net.ipv4.conf.all.rp_filter")
	add(fmt.Sprintf("  %s rp_filter               %s%s%s  (%s)", boolOK(rpfall, "1"), info,
		map[string]string{"0": "disabled", "1": "strict", "2": "loose"}[rpfall], RESET, rpfall))

	redir := readSysctl("net.ipv4.conf.all.accept_redirects")
	add(fmt.Sprintf("  %s accept_redirects         %s%s%s  (%s)", boolOK(redir, "0"), info,
		map[string]string{"0": "disabled (safe)", "1": "enabled"}[redir], RESET, redir))

	martians := readSysctl("net.ipv4.conf.all.log_martians")
	add(fmt.Sprintf("  %s log_martians             %s%s%s  (%s)", boolOK(martians, "1"), info,
		map[string]string{"0": "disabled", "1": "enabled"}[martians], RESET, martians))

	ts := readSysctl("net.ipv4.tcp_timestamps")
	add(fmt.Sprintf("  %s tcp_timestamps           %s%s%s  (%s)", boolOK(ts, "0"), info,
		map[string]string{"0": "disabled (safe)", "1": "leaks uptime info"}[ts], RESET, ts))

	bpfjit := readSysctl("net.core.bpf_jit_harden")
	add(fmt.Sprintf("  %s bpf_jit_harden           %s%s%s  (%s)", boolOK(bpfjit, "1", "2"), info,
		map[string]string{"0": "disabled", "1": "unprivileged", "2": "all"}[bpfjit], RESET, bpfjit))

	sysrq := readSysctl("kernel.sysrq")
	sysrqSt := ok
	if sysrq == "1" {
		sysrqSt = warn
	}
	add(fmt.Sprintf("  %s sysrq                   %s%s%s  (%s)", sysrqSt, info,
		map[string]string{"0": "disabled", "1": "all keys enabled", "176": "safe subset"}[sysrq], RESET, sysrq))

	udpN := countUDPListen()
	add(fmt.Sprintf("  %s UDP sockets              %s%d active%s", ok, info, udpN, RESET))

	blank()

	// ── users & access ────────────────────────────────────────────────────────
	add(hc + " ── users & access" + RESET)

	totalU, loginU := countShellUsers()
	add(fmt.Sprintf("  %s shell users              %stotal:%d  with-login:%d%s", ok, info, totalU, loginU, RESET))

	sshKeys := checkSSHAuthKeys()
	sshSt := ok
	sshNote := "none found"
	if len(sshKeys) > 0 {
		sshNote = fmt.Sprintf("%d users: %s", len(sshKeys), strings.Join(sshKeys, ", "))
	}
	add(fmt.Sprintf("  %s authorized_keys          %s%s%s", sshSt, info, sshNote, RESET))

	add(hc + " ── logged-in users" + RESET)
	if ui.Anon {
		add(info + "  [ANON]" + RESET)
	} else {
		users := readLoggedUsers()
		if len(users) == 0 {
			add(info + "  (none / who unavailable)" + RESET)
		} else {
			for _, u := range users {
				add("  " + u)
			}
		}
	}

	blank()

	// ── external connections ──────────────────────────────────────────────────
	add(hc + " ── established connections" + RESET)
	conns := readEstablished()
	external := 0
	for _, c := range conns {
		if !isPrivateIP(c.Remote) {
			external++
		}
	}
	add(fmt.Sprintf("  %s connections              %stotal:%d  external:%d%s",
		ok, info, len(conns), external, RESET))
	if !ui.Anon {
		shown := 0
		for _, c := range conns {
			if isPrivateIP(c.Remote) {
				continue
			}
			if shown >= 6 {
				break
			}
			add(fmt.Sprintf("          %s→ %s%s", ansiCol(t.NET), c.Remote, RESET))
			shown++
		}
	}

	// ── render with scroll ────────────────────────────────────────────────────
	displayRows := rows - 2
	maxScroll := max(0, len(vbuf)-displayRows)
	if ui.SecScroll > maxScroll {
		ui.SecScroll = maxScroll
	}
	row := 1
	for i := ui.SecScroll; i < len(vbuf) && row < rows-1; i++ {
		buf.WriteString(pos(row, 0))
		buf.WriteString(clampVisual(vbuf[i].s, cols) + CLEOL)
		row++
	}
	for ; row < rows-1; row++ {
		buf.WriteString(pos(row, 0) + CLEOL)
	}

	drawStatusBar(buf, rows, cols, ui, ui.Interval, ss, t)
}

func aslrDesc(v string) string {
	switch v {
	case "0": return "disabled"
	case "1": return "conservative"
	case "2": return "full"
	default:  return "unknown"
	}
}

func kptrDesc(v string) string {
	switch v {
	case "0": return "kernel pointers exposed"
	case "1": return "restricted (non-root)"
	case "2": return "hidden from all"
	default:  return "unknown"
	}
}
