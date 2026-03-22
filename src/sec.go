package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var secCache struct {
	suid, sgid, wwEtc int
	t                 time.Time
}

const secFindTTL = 60 * time.Second

func cachedCountSUID() int {
	if time.Since(secCache.t) > secFindTTL {
		secCache.suid = countSUIDBinaries()
		secCache.sgid = countSGIDBinaries()
		secCache.wwEtc = checkWorldWritableEtc()
		secCache.t = time.Now()
	}
	return secCache.suid
}

func cachedCountSGID() int  { cachedCountSUID(); return secCache.sgid }
func cachedWWEtc() int      { cachedCountSUID(); return secCache.wwEtc }

func readSysctl(key string) string {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	v, err := os.ReadFile(path)
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(v))
}

func visualLen(s string) int {
	n := 0
	i := 0
	for i < len(s) {
		b := s[i]
		if b == '\033' {
			j := i + 1
			if j < len(s) && s[j] == '[' {
				j++
				for j < len(s) && !((s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z')) {
					j++
				}
				if j < len(s) {
					j++
				}
			}
			i = j
		} else if b >= 0x80 && b < 0xC0 {
			i++
		} else {
			n++
			i++
		}
	}
	return n
}

func padRight(s string, w int) string {
	vl := visualLen(s)
	if vl >= w {
		return clampVisual(s, w)
	}
	return s + strings.Repeat(" ", w-vl)
}

type secListenPort struct {
	Proto string
	Port  int
}

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
		ak := f[5] + "/.ssh/authorized_keys"
		if info, err := os.Stat(ak); err == nil && info.Size() > 0 {
			found = append(found, f[0])
		}
	}
	return found
}

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

func countSUIDBinaries() int {
	out := runCmd(2000000000, "find", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
		"-perm", "/4000", "-type", "f")
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if l != "" {
			n++
		}
	}
	return n
}

func countSGIDBinaries() int {
	out := runCmd(2000000000, "find", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
		"-perm", "/2000", "-type", "f")
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
	return strings.HasPrefix(v, "|"), v
}

func checkTmpSticky() bool {
	info, err := os.Stat("/tmp")
	if err != nil {
		return false
	}
	return info.Mode()&01000 != 0
}

type netConn struct {
	Local  string
	Remote string
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
			if len(f) < 4 || f[3] != "01" {
				continue
			}
			out = append(out, netConn{Local: hexAddrToIP(f[1]), Remote: hexAddrToIP(f[2])})
		}
	}
	return out
}

func hexAddrToIP(s string) string {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return s
	}
	port, _ := strconv.ParseInt(parts[1], 16, 32)
	if len(parts[0]) == 8 {
		v, _ := strconv.ParseUint(parts[0], 16, 32)
		return fmt.Sprintf("%d.%d.%d.%d:%d", byte(v), byte(v>>8), byte(v>>16), byte(v>>24), port)
	}
	return fmt.Sprintf("%s:%d", parts[0], port)
}

func isPrivateIP(addr string) bool {
	for _, pfx := range []string{"127.", "10.", "192.168.", "::1", "0.0.0.0"} {
		if strings.HasPrefix(addr, pfx) {
			return true
		}
	}
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

func checkFirejail() (installed bool, running int) {
	for _, p := range []string{"/usr/bin/firejail", "/usr/local/bin/firejail"} {
		if _, err := os.Stat(p); err == nil {
			installed = true
			break
		}
	}
	if installed {
		entries, err := os.ReadDir("/run/firejail")
		if err == nil {
			for _, e := range entries {
				if e.IsDir() {
					running++
				}
			}
		}
	}
	return
}

func checkKernelLockdown() string {
	raw, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return "n/a"
	}
	for _, part := range strings.Fields(strings.TrimSpace(string(raw))) {
		if strings.HasPrefix(part, "[") {
			return strings.Trim(part, "[]")
		}
	}
	return "?"
}

func countSeccompProcs() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		raw, err := os.ReadFile("/proc/" + name + "/status")
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "Seccomp:") {
				f := strings.Fields(line)
				if len(f) >= 2 && f[1] == "2" {
					n++
				}
				break
			}
		}
	}
	return n
}

func checkIMA() bool {
	_, err := os.Stat("/sys/kernel/security/ima/policy")
	return err == nil
}

func checkPortOpen(ports []secListenPort, port int) bool {
	for _, p := range ports {
		if p.Port == port {
			return true
		}
	}
	return false
}

func readSSHConfig() map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile("/etc/ssh/sshd_config")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 {
			out[strings.ToLower(f[0])] = f[1]
		}
	}
	return out
}

func checkWorldWritableEtc() int {
	out := runCmd(5000000000, "find", "/etc", "-maxdepth", "3", "-perm", "-002", "-type", "f")
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if l != "" {
			n++
		}
	}
	return n
}

func checkFilePerms(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "n/a"
	}
	return fmt.Sprintf("%04o", info.Mode().Perm())
}

func checkSudoersNopasswd() bool {
	check := func(path string) bool {
		raw, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "NOPASSWD") {
				return true
			}
		}
		return false
	}
	if check("/etc/sudoers") {
		return true
	}
	entries, err := os.ReadDir("/etc/sudoers.d")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if check("/etc/sudoers.d/" + e.Name()) {
			return true
		}
	}
	return false
}

func checkSecTools() map[string]bool {
	tools := []string{"lynis", "rkhunter", "chkrootkit", "aide", "clamscan", "debsums", "tiger"}
	out := map[string]bool{}
	for _, t := range tools {
		_, err := exec.LookPath(t)
		out[t] = err == nil
	}
	return out
}

func lynisScore() string {
	for _, path := range []string{"/var/log/lynis-report.dat", "/var/log/lynis/lynis-report.dat"} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(line, "hardening_index=") {
				return strings.TrimPrefix(line, "hardening_index=")
			}
		}
	}
	return ""
}

func drawSEC(buf *strings.Builder, rows, cols int, ss *SysState, ui *UI, t *Theme) {
	hdr := clampStr(" SEC"+strings.Repeat("─", max(0, cols-4)), cols)
	buf.WriteString(pos(0, 0))
	buf.WriteString(ansiCol(t.HDR) + BOLD + hdr + RESET + CLEOL)

	lw := cols/2 - 1
	rw := cols - lw - 1

	var lbuf, rbuf []string
	addL := func(s string) { lbuf = append(lbuf, s) }
	addR := func(s string) { rbuf = append(rbuf, s) }

	ok   := ansiCol(t.DISK) + BOLD + "OK  " + RESET
	warn := ansiCol(t.WARN) + BOLD + "WARN" + RESET
	part := ansiCol(t.RAM)  + BOLD + "PART" + RESET
	info := DIM + ansiCol(t.USB)
	_ = part

	ph := func(label string, w int) string {
		pad := max(0, w-5-visualLen(label))
		return ansiCol(t.HDR) + BOLD + " ── " + label + " " + strings.Repeat("─", pad) + RESET
	}

	boolOK := func(v string, good ...string) string {
		for _, g := range good {
			if v == g {
				return ok
			}
		}
		return warn
	}

	row := func(st, label, val string) string {
		return fmt.Sprintf("  %s %-20s %s%s%s", st, label, info, val, RESET)
	}

	warnLine := func(s string) string {
		return fmt.Sprintf("         %s! %s%s", ansiCol(t.WARN), s, RESET)
	}

	ss.mu.RLock()
	vms := ss.VMs
	ss.mu.RUnlock()

	// LEFT COLUMN

	addL(ph("kernel hardening", lw))

	aslr := readSysctl("kernel.randomize_va_space")
	aslrSt := warn
	if aslr == "2" {
		aslrSt = ok
	} else if aslr == "1" {
		aslrSt = part
	}
	addL(row(aslrSt, "ASLR", aslrDesc(aslr)+" ("+aslr+")"))

	kptr := readSysctl("kernel.kptr_restrict")
	addL(row(boolOK(kptr, "1", "2"), "kptr_restrict", kptrDesc(kptr)+" ("+kptr+")"))

	dmesg := readSysctl("kernel.dmesg_restrict")
	addL(row(boolOK(dmesg, "1"), "dmesg_restrict",
		map[string]string{"0": "readable by all", "1": "root only", "?": "n/a"}[dmesg]+" ("+dmesg+")"))

	perf := readSysctl("kernel.perf_event_paranoid")
	perfSt := ok
	if perf == "-1" || perf == "0" {
		perfSt = warn
	}
	addL(row(perfSt, "perf_paranoid", "level "+perf))

	ptrace := readSysctl("kernel.yama.ptrace_scope")
	addL(row(boolOK(ptrace, "1", "2", "3"), "ptrace_scope",
		map[string]string{"0": "unrestricted", "1": "parent only", "2": "admin only", "3": "disabled", "?": "Yama n/a"}[ptrace]+" ("+ptrace+")"))

	suidD := readSysctl("fs.suid_dumpable")
	addL(row(boolOK(suidD, "0"), "suid_dumpable",
		map[string]string{"0": "disabled", "1": "enabled", "2": "suidsafe", "?": "?"}[suidD]+" ("+suidD+")"))

	bpf := readSysctl("kernel.unprivileged_bpf_disabled")
	addL(row(boolOK(bpf, "1", "2"), "unpriv_bpf",
		map[string]string{"0": "allowed", "1": "disabled", "2": "admin only", "?": "n/a"}[bpf]+" ("+bpf+")"))

	userns := readSysctl("kernel.unprivileged_userns_clone")
	usernsGood := userns == "0" || userns == "?"
	usernsLabel := map[string]string{"0": "disabled", "1": "allowed", "?": "n/a"}[userns]
	usernsX := ok
	if !usernsGood {
		usernsX = warn
	}
	addL(row(usernsX, "unpriv_userns", usernsLabel+" ("+userns+")"))

	kexec := readSysctl("kernel.kexec_load_disabled")
	addL(row(boolOK(kexec, "1"), "kexec_disabled",
		map[string]string{"0": "kexec allowed", "1": "kexec disabled", "?": "n/a"}[kexec]+" ("+kexec+")"))

	symlinks := readSysctl("fs.protected_symlinks")
	hardlinks := readSysctl("fs.protected_hardlinks")
	addL(row(boolOK(symlinks, "1"), "protected_symlinks", map[string]string{"0": "off", "1": "on", "?": "?"}[symlinks]))
	addL(row(boolOK(hardlinks, "1"), "protected_hardlinks", map[string]string{"0": "off", "1": "on", "?": "?"}[hardlinks]))

	ipfwd := readSysctl("net.ipv4.ip_forward")
	ipfwdSt := ok
	if ipfwd == "1" {
		ipfwdSt = warn
	}
	addL(row(ipfwdSt, "ip_forward",
		map[string]string{"0": "off", "1": "ON — routing enabled", "?": "?"}[ipfwd]))

	moddis := readSysctl("kernel.modules_disabled")
	addL(row(boolOK(moddis, "1"), "modules_disabled",
		map[string]string{"0": "modules loadable", "1": "locked", "?": "n/a"}[moddis]+" ("+moddis+")"))

	lockdown := checkKernelLockdown()
	ldSt := ok
	if lockdown == "none" || lockdown == "n/a" {
		ldSt = warn
	}
	addL(row(ldSt, "kernel lockdown", lockdown))

	addL("")

	addL(ph("kernel taint", lw))
	taintVal, taintMsgs := readTaint()
	if taintVal == 0 {
		addL(row(ok, "tainted", "0 — clean"))
	} else {
		addL(row(warn, "tainted", fmt.Sprintf("%d", taintVal)))
		for _, msg := range taintMsgs {
			addL(warnLine(msg))
		}
	}

	addL("")

	addL(ph("rootkit indicators", lw))

	procN, lavgN, delta := hiddenProcDelta()
	hdSt := ok
	hdNote := fmt.Sprintf("/proc:%d  lavg:%d  Δ:%d", procN, lavgN, delta)
	if delta > 5 {
		hdSt = warn
		hdNote += " — HIDDEN"
	}
	addL(row(hdSt, "hidden procs", hdNote))

	preloads := checkLdPreload()
	plSt := ok
	if len(preloads) > 0 {
		plSt = warn
	}
	addL(row(plSt, "LD_PRELOAD inject", fmt.Sprintf("%d processes", len(preloads))))
	for _, p := range preloads {
		addL(warnLine(p))
	}

	kallLeak := checkKallsymsLeak()
	kallSt := ok
	kallNote := "addresses hidden"
	if kallLeak {
		kallSt = warn
		kallNote = "real addrs visible!"
	}
	addL(row(kallSt, "kallsyms leak", kallNote))

	rawN := countRawSockets()
	rawSt := ok
	rawNote := fmt.Sprintf("%d sockets", rawN)
	if rawN > 2 {
		rawSt = warn
		rawNote += " — check sniffers"
	}
	addL(row(rawSt, "raw sockets", rawNote))

	unsignedMods := readUnsignedModules()
	modSt := ok
	if len(unsignedMods) > 0 {
		modSt = warn
	}
	addL(row(modSt, "unsigned modules", fmt.Sprintf("%d OOT/unsigned", len(unsignedMods))))
	for _, m := range unsignedMods {
		addL(warnLine(m))
	}

	suids := cachedCountSUID()
	suidSt := ok
	suidNote := fmt.Sprintf("%d binaries", suids)
	if suids > 30 {
		suidSt = warn
		suidNote += " — high"
	}
	addL(row(suidSt, "SUID", suidNote))

	sgids := cachedCountSGID()
	sgidSt := ok
	sgidNote := fmt.Sprintf("%d binaries", sgids)
	if sgids > 20 {
		sgidSt = warn
		sgidNote += " — high"
	}
	addL(row(sgidSt, "SGID", sgidNote))

	globalPre := checkGlobalPreload()
	glSt := ok
	glNote := "clean"
	if len(globalPre) > 0 {
		glSt = warn
		glNote = fmt.Sprintf("%d entries!", len(globalPre))
	}
	addL(row(glSt, "ld.so.preload", glNote))
	for _, p := range globalPre {
		addL(warnLine(p))
	}

	corePiped, corePattern := checkCorePatternPipe()
	cpSt := ok
	if corePiped {
		cpSt = warn
	}
	addL(row(cpSt, "core_pattern", corePattern))

	tmpSt := ok
	tmpNote := "sticky bit set"
	if !checkTmpSticky() {
		tmpSt = warn
		tmpNote = "no sticky bit!"
	}
	addL(row(tmpSt, "/tmp sticky", tmpNote))

	imaSt := ok
	imaNote := "IMA inactive"
	if checkIMA() {
		imaNote = "IMA policy active"
	} else {
		imaSt = warn
	}
	addL(row(imaSt, "IMA", imaNote))

	addL("")

	addL(ph("filesystem", lw))

	wwCount := cachedWWEtc()
	wwSt := ok
	wwNote := "none"
	if wwCount > 0 {
		wwSt = warn
		wwNote = fmt.Sprintf("%d world-writable files!", wwCount)
	}
	addL(row(wwSt, "world-writable /etc", wwNote))

	shadowPerms := checkFilePerms("/etc/shadow")
	shadowSt := ok
	if shadowPerms != "0640" && shadowPerms != "0000" && shadowPerms != "n/a" {
		shadowSt = warn
	}
	addL(row(shadowSt, "/etc/shadow perms", shadowPerms))

	passwdPerms := checkFilePerms("/etc/passwd")
	passwdSt := ok
	if passwdPerms != "0644" && passwdPerms != "n/a" {
		passwdSt = warn
	}
	addL(row(passwdSt, "/etc/passwd perms", passwdPerms))

	nopasswd := checkSudoersNopasswd()
	nopasswdSt := ok
	nopasswdNote := "not found"
	if nopasswd {
		nopasswdSt = warn
		nopasswdNote = "NOPASSWD found!"
	}
	addL(row(nopasswdSt, "sudoers NOPASSWD", nopasswdNote))

	// RIGHT COLUMN

	addR(ph("firewall & sandbox", rw))

	aaSt := warn
	if vms.AppArmor {
		aaSt = ok
	}
	addR(row(aaSt, "AppArmor", map[bool]string{true: "active", false: "inactive"}[vms.AppArmor]))

	seSt := warn
	if vms.SELinux {
		seSt = ok
	}
	addR(row(seSt, "SELinux", map[bool]string{true: "enforcing", false: "inactive"}[vms.SELinux]))

	fwSt := warn
	fw := vms.Firewall
	if fw == "" {
		fw = "none detected"
	} else {
		fwSt = ok
	}
	addR(row(fwSt, "Firewall", fw))

	fjInst, fjRun := checkFirejail()
	fjSt := warn
	fjNote := "not installed"
	if fjInst {
		fjSt = ok
		fjNote = fmt.Sprintf("installed  sandboxes: %d", fjRun)
	}
	addR(row(fjSt, "Firejail", fjNote))

	seccompN := countSeccompProcs()
	secSt := ok
	secNote := fmt.Sprintf("%d procs with seccomp filter", seccompN)
	if seccompN == 0 {
		secSt = warn
		secNote = "0 — no seccomp sandboxing"
	}
	addR(row(secSt, "seccomp (filter)", secNote))

	swapEnc := "?"
	if raw, err := os.ReadFile("/proc/swaps"); err == nil {
		if strings.Contains(string(raw), "dm-") || strings.Contains(string(raw), "zram") {
			swapEnc = "zram/encrypted"
		} else if strings.Count(string(raw), "\n") > 1 {
			swapEnc = "plain — unencrypted"
		} else {
			swapEnc = "none"
		}
	}
	swapSt := ok
	if swapEnc == "plain — unencrypted" {
		swapSt = warn
	}
	addR(row(swapSt, "swap", swapEnc))

	addR("")

	addR(ph("network security", rw))

	syncook := readSysctl("net.ipv4.tcp_syncookies")
	addR(row(boolOK(syncook, "1"), "tcp_syncookies",
		map[string]string{"0": "disabled", "1": "SYN flood protection", "?": "?"}[syncook]))

	rpfall := readSysctl("net.ipv4.conf.all.rp_filter")
	addR(row(boolOK(rpfall, "1"), "rp_filter",
		map[string]string{"0": "disabled", "1": "strict", "2": "loose", "?": "?"}[rpfall]))

	redir := readSysctl("net.ipv4.conf.all.accept_redirects")
	addR(row(boolOK(redir, "0"), "accept_redirects",
		map[string]string{"0": "disabled (safe)", "1": "enabled — MITM risk", "?": "?"}[redir]))

	martians := readSysctl("net.ipv4.conf.all.log_martians")
	addR(row(boolOK(martians, "1"), "log_martians",
		map[string]string{"0": "disabled", "1": "enabled", "?": "?"}[martians]))

	ts := readSysctl("net.ipv4.tcp_timestamps")
	addR(row(boolOK(ts, "0"), "tcp_timestamps",
		map[string]string{"0": "disabled (safe)", "1": "leaks uptime info", "?": "?"}[ts]))

	bpfjit := readSysctl("net.core.bpf_jit_harden")
	addR(row(boolOK(bpfjit, "1", "2"), "bpf_jit_harden",
		map[string]string{"0": "disabled", "1": "unprivileged", "2": "all", "?": "?"}[bpfjit]))

	sysrq := readSysctl("kernel.sysrq")
	sysrqSt := ok
	if sysrq == "1" {
		sysrqSt = warn
	}
	addR(row(sysrqSt, "sysrq",
		map[string]string{"0": "disabled", "1": "all keys — dangerous", "176": "safe subset", "?": "?"}[sysrq]))

	addR("")

	addR(ph("network vulnerabilities", rw))

	srcRoute4 := readSysctl("net.ipv4.conf.all.accept_source_route")
	addR(row(boolOK(srcRoute4, "0"), "source_route ipv4",
		map[string]string{"0": "blocked (safe)", "1": "ENABLED — spoofing risk", "?": "?"}[srcRoute4]))

	srcRoute6 := readSysctl("net.ipv6.conf.all.accept_source_route")
	addR(row(boolOK(srcRoute6, "0", "-1"), "source_route ipv6",
		map[string]string{"0": "blocked", "-1": "blocked", "1": "ENABLED — spoofing", "?": "?"}[srcRoute6]))

	sendRedir := readSysctl("net.ipv4.conf.all.send_redirects")
	addR(row(boolOK(sendRedir, "0"), "send_redirects",
		map[string]string{"0": "disabled (safe)", "1": "ENABLED — MITM vector", "?": "?"}[sendRedir]))

	bogus := readSysctl("net.ipv4.icmp_ignore_bogus_error_responses")
	addR(row(boolOK(bogus, "1"), "icmp_bogus_ignore",
		map[string]string{"0": "log bogus errors", "1": "ignored (safe)", "?": "?"}[bogus]))

	rfc1337 := readSysctl("net.ipv4.tcp_rfc1337")
	addR(row(boolOK(rfc1337, "1"), "tcp_rfc1337",
		map[string]string{"0": "TIME_WAIT vuln open", "1": "protected", "?": "?"}[rfc1337]))

	tempaddr := readSysctl("net.ipv6.conf.all.use_tempaddr")
	addR(row(boolOK(tempaddr, "2"), "ipv6 privacy",
		map[string]string{"0": "disabled", "1": "temporary addr", "2": "prefer temp (safe)", "?": "?"}[tempaddr]))

	redir6 := readSysctl("net.ipv6.conf.all.accept_redirects")
	addR(row(boolOK(redir6, "0"), "ipv6 redirects",
		map[string]string{"0": "disabled (safe)", "1": "ENABLED — MITM risk", "?": "?"}[redir6]))

	icmpRatelimit := readSysctl("net.ipv4.icmp_ratelimit")
	icmpRSt := ok
	if icmpRatelimit == "0" {
		icmpRSt = warn
	}
	addR(row(icmpRSt, "icmp_ratelimit", icmpRatelimit+" ms (0=unlimited)"))

	ports := readListenPorts()

	if checkPortOpen(ports, 53) {
		addR(row(warn, "DNS port 53", "LISTENING — open resolver risk"))
	} else {
		addR(row(ok, "DNS port 53", "not listening"))
	}

	if checkPortOpen(ports, 25) || checkPortOpen(ports, 587) {
		addR(row(warn, "SMTP 25/587", "LISTENING — open relay check"))
	} else {
		addR(row(ok, "SMTP 25/587", "not listening"))
	}

	udpN := countUDPListen()
	udpSt := ok
	if udpN > 10 {
		udpSt = warn
	}
	addR(row(udpSt, "UDP sockets", fmt.Sprintf("%d active", udpN)))

	addR("")

	addR(ph("SSH hardening", rw))
	if _, err := os.Stat("/etc/ssh/sshd_config"); err != nil {
		addR(info + "  sshd not found" + RESET)
	} else {
		sshCfg := readSSHConfig()
		sshCheck := func(key, goodVal, label string) {
			v, ok2 := sshCfg[strings.ToLower(key)]
			if !ok2 {
				addR(row(ok, label, "n/a (default)"))
				return
			}
			st := ok
			if strings.ToLower(v) != goodVal {
				st = warn
			}
			addR(row(st, label, v))
		}
		sshCheck("PermitRootLogin", "no", "PermitRootLogin")
		sshCheck("PasswordAuthentication", "no", "PasswordAuth")
		sshCheck("X11Forwarding", "no", "X11Forwarding")
		sshCheck("PermitEmptyPasswords", "no", "PermitEmptyPwd")
		sshCheck("Protocol", "2", "Protocol")

		if v, exists := sshCfg["maxauthtries"]; exists {
			n, err := strconv.Atoi(v)
			st := ok
			if err != nil || n > 4 {
				st = warn
			}
			addR(row(st, "MaxAuthTries", v))
		} else {
			addR(row(ok, "MaxAuthTries", "n/a (default)"))
		}
	}

	addR("")

	addR(ph("security tools", rw))
	secTools := checkSecTools()
	toolOrder := []string{"lynis", "rkhunter", "chkrootkit", "aide", "clamscan", "debsums", "tiger"}
	for _, tool := range toolOrder {
		inst := secTools[tool]
		st := ok
		note := "installed"
		if !inst {
			st = warn
			note = "not found"
		}
		if tool == "lynis" && inst {
			if score := lynisScore(); score != "" {
				note = "installed  score: " + score
			}
		}
		addR(row(st, tool, note))
	}

	addR("")

	addR(ph("listening ports", rw))
	if len(ports) == 0 {
		addR(info + "  (none)" + RESET)
	} else {
		line := "  "
		for i, p := range ports {
			if i > 0 {
				line += "  "
			}
			entry := fmt.Sprintf("%s%s:%d%s", ansiCol(t.NET), p.Proto, p.Port, RESET)
			if visualLen(line+entry) > rw-2 {
				addR(line)
				line = "  "
			}
			line += entry
		}
		if line != "  " {
			addR(line)
		}
	}

	addR("")

	addR(ph("established connections", rw))
	conns := readEstablished()
	external := 0
	for _, c := range conns {
		if !isPrivateIP(c.Remote) {
			external++
		}
	}
	extSt := ok
	if external > 0 {
		extSt = warn
	}
	addR(row(extSt, "connections", fmt.Sprintf("total:%d  external:%d", len(conns), external)))
	if !ui.Anon {
		shown := 0
		for _, c := range conns {
			if isPrivateIP(c.Remote) {
				continue
			}
			if shown >= 8 {
				addR(warnLine(fmt.Sprintf("... and %d more", external-shown)))
				break
			}
			addR(warnLine("→ " + c.Remote))
			shown++
		}
	}

	addR("")

	addR(ph("users & access", rw))

	totalU, loginU := countShellUsers()
	addR(row(ok, "shell users", fmt.Sprintf("total:%d  with-login:%d", totalU, loginU)))

	sshKeys := checkSSHAuthKeys()
	sshSt := ok
	sshNote := "none"
	if len(sshKeys) > 0 {
		sshNote = strings.Join(sshKeys, " ")
	}
	addR(row(sshSt, "authorized_keys", sshNote))

	if ui.Anon {
		addR(row(ok, "logged in", info+"[ANON]"+RESET))
	} else {
		users := readLoggedUsers()
		if len(users) == 0 {
			addR(row(ok, "logged in", "(none)"))
		} else {
			addR(row(ok, "logged in", fmt.Sprintf("%d sessions", len(users))))
			for _, u := range users {
				addR("    " + u)
			}
		}
	}

	displayRows := rows - 2
	total := max(len(lbuf), len(rbuf))
	maxScroll := max(0, total-displayRows)
	if ui.SecScroll > maxScroll {
		ui.SecScroll = maxScroll
	}

	div := DIM + "│" + RESET
	renderRow := 1
	for i := ui.SecScroll; i < total && renderRow < rows-1; i++ {
		buf.WriteString(pos(renderRow, 0))
		ls := ""
		if i < len(lbuf) {
			ls = lbuf[i]
		}
		rs := ""
		if i < len(rbuf) {
			rs = rbuf[i]
		}
		buf.WriteString(padRight(ls, lw))
		buf.WriteString(div)
		buf.WriteString(clampVisual(rs, rw))
		buf.WriteString(CLEOL)
		renderRow++
	}
	for ; renderRow < rows-1; renderRow++ {
		buf.WriteString(pos(renderRow, 0) + CLEOL)
	}

	drawStatusBar(buf, rows, cols, ui, ui.Interval, ss, t)
}

func aslrDesc(v string) string {
	switch v {
	case "0":
		return "disabled"
	case "1":
		return "conservative"
	case "2":
		return "full"
	default:
		return "unknown"
	}
}

func kptrDesc(v string) string {
	switch v {
	case "0":
		return "kernel pointers exposed"
	case "1":
		return "restricted (non-root)"
	case "2":
		return "hidden from all"
	default:
		return "unknown"
	}
}
