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
	ss.mu.RLock()
	vms := ss.VMs
	ss.mu.RUnlock()

	ok   := t.DISK
	warn := t.WARN
	inf  := t.USB

	bc := func(good bool) Color {
		if good { return ok }
		return warn
	}

	lbl := func(label, val string, c Color) ColLine {
		return ColLine{Text: fmt.Sprintf("  %-16s %s", label, val), C: c}
	}
	hdr := func(name string) ColLine {
		return ColLine{Text: " " + name, C: t.HDR, Bold: true}
	}

	var lines []ColLine
	add  := func(l ColLine)               { lines = append(lines, l) }
	addl := func(label, val string, c Color) { add(lbl(label, val, c)) }
	addh := func(name string)              { add(hdr(name)) }

	// kernel hardening
	addh("kernel hardening")
	aslr := readSysctl("kernel.randomize_va_space")
	addl("ASLR", aslrDesc(aslr)+" ("+aslr+")", bc(aslr == "2"))
	kptr := readSysctl("kernel.kptr_restrict")
	addl("kptr_restrict", kptrDesc(kptr)+" ("+kptr+")", bc(kptr != "0"))
	dmesg := readSysctl("kernel.dmesg_restrict")
	addl("dmesg_restrict", map[string]string{"0":"all users","1":"root only","?":"n/a"}[dmesg]+" ("+dmesg+")", bc(dmesg == "1"))
	perf := readSysctl("kernel.perf_event_paranoid")
	addl("perf_paranoid", "level "+perf, bc(perf != "-1" && perf != "0"))
	ptrace := readSysctl("kernel.yama.ptrace_scope")
	addl("ptrace_scope", map[string]string{"0":"unrestricted","1":"parent-only","2":"admin-only","3":"disabled","?":"n/a"}[ptrace]+" ("+ptrace+")", bc(ptrace != "0"))
	suidD := readSysctl("fs.suid_dumpable")
	addl("suid_dumpable", map[string]string{"0":"disabled","1":"enabled","2":"suidsafe","?":"?"}[suidD]+" ("+suidD+")", bc(suidD == "0"))
	bpf := readSysctl("kernel.unprivileged_bpf_disabled")
	addl("unpriv_bpf", map[string]string{"0":"allowed","1":"disabled","2":"admin","?":"n/a"}[bpf]+" ("+bpf+")", bc(bpf == "1" || bpf == "2"))
	userns := readSysctl("kernel.unprivileged_userns_clone")
	addl("unpriv_userns", map[string]string{"0":"disabled","1":"allowed","?":"n/a"}[userns]+" ("+userns+")", bc(userns == "0" || userns == "?"))
	kexec := readSysctl("kernel.kexec_load_disabled")
	addl("kexec_disabled", map[string]string{"0":"allowed","1":"locked","?":"n/a"}[kexec]+" ("+kexec+")", bc(kexec == "1"))
	addl("protected_symlinks", map[string]string{"0":"off","1":"on","?":"?"}[readSysctl("fs.protected_symlinks")], bc(readSysctl("fs.protected_symlinks") == "1"))
	addl("protected_hardlinks", map[string]string{"0":"off","1":"on","?":"?"}[readSysctl("fs.protected_hardlinks")], bc(readSysctl("fs.protected_hardlinks") == "1"))
	ipfwd := readSysctl("net.ipv4.ip_forward")
	addl("ip_forward", map[string]string{"0":"off","1":"ON — routing","?":"?"}[ipfwd], bc(ipfwd != "1"))
	moddis := readSysctl("kernel.modules_disabled")
	addl("modules_disabled", map[string]string{"0":"loadable","1":"locked","?":"n/a"}[moddis]+" ("+moddis+")", bc(moddis == "1"))
	lockdown := checkKernelLockdown()
	addl("lockdown", lockdown, bc(lockdown != "none" && lockdown != "n/a"))

	// kernel taint
	addh("kernel taint")
	taintVal, taintMsgs := readTaint()
	if taintVal == 0 {
		addl("tainted", "0 — clean", ok)
	} else {
		addl("tainted", fmt.Sprintf("%d", taintVal), warn)
		for _, msg := range taintMsgs {
			add(ColLine{Text: "   ! " + msg, C: warn})
		}
	}

	// rootkit
	addh("rootkit")
	procN, lavgN, delta := hiddenProcDelta()
	addl("hidden procs", fmt.Sprintf("/proc:%d lavg:%d Δ:%d", procN, lavgN, delta), bc(delta <= 5))
	pls := checkLdPreload()
	addl("LD_PRELOAD", fmt.Sprintf("%d procs", len(pls)), bc(len(pls) == 0))
	for _, p := range pls { add(ColLine{Text: "   → " + p, C: warn}) }
	kallNote := "addresses hidden"
	if checkKallsymsLeak() { kallNote = "real addrs visible!" }
	addl("kallsyms", kallNote, bc(!checkKallsymsLeak()))
	rawN := countRawSockets()
	addl("raw sockets", fmt.Sprintf("%d", rawN), bc(rawN <= 2))
	unsig := readUnsignedModules()
	addl("unsigned modules", fmt.Sprintf("%d OOT/unsigned", len(unsig)), bc(len(unsig) == 0))
	for _, m := range unsig { add(ColLine{Text: "   ! " + m, C: warn}) }
	suids := cachedCountSUID()
	addl("SUID", fmt.Sprintf("%d bins", suids), bc(suids <= 30))
	sgids := cachedCountSGID()
	addl("SGID", fmt.Sprintf("%d bins", sgids), bc(sgids <= 20))
	gl := checkGlobalPreload()
	addl("ld.so.preload", fmt.Sprintf("%d entries", len(gl)), bc(len(gl) == 0))
	for _, p := range gl { add(ColLine{Text: "   ! " + p, C: warn}) }
	corePiped, corePattern := checkCorePatternPipe()
	addl("core_pattern", corePattern, bc(!corePiped))
	addl("/tmp sticky", map[bool]string{true:"set",false:"MISSING"}[checkTmpSticky()], bc(checkTmpSticky()))
	addl("IMA", map[bool]string{true:"policy active",false:"inactive"}[checkIMA()], bc(checkIMA()))

	// filesystem
	addh("filesystem")
	wwCount := cachedWWEtc()
	addl("world-writable /etc", fmt.Sprintf("%d files", wwCount), bc(wwCount == 0))
	addl("/etc/shadow", checkFilePerms("/etc/shadow"), bc(checkFilePerms("/etc/shadow") == "640" || checkFilePerms("/etc/shadow") == "000" || checkFilePerms("/etc/shadow") == "000"))
	addl("/etc/passwd", checkFilePerms("/etc/passwd"), bc(checkFilePerms("/etc/passwd") == "644"))
	addl("sudoers NOPASSWD", map[bool]string{true:"FOUND",false:"clean"}[checkSudoersNopasswd()], bc(!checkSudoersNopasswd()))

	// firewall & sandbox
	addh("firewall & sandbox")
	addl("AppArmor", map[bool]string{true:"active",false:"inactive"}[vms.AppArmor], bc(vms.AppArmor))
	addl("SELinux", map[bool]string{true:"enforcing",false:"inactive"}[vms.SELinux], bc(vms.SELinux))
	fw := vms.Firewall; if fw == "" { fw = "none detected" }
	addl("firewall", fw, bc(vms.Firewall != ""))
	fjInst, fjRun := checkFirejail()
	fjNote := fmt.Sprintf("installed  sandboxes:%d", fjRun)
	if !fjInst { fjNote = "not installed" }
	addl("firejail", fjNote, bc(fjInst))
	scN := countSeccompProcs()
	addl("seccomp (filter)", fmt.Sprintf("%d procs", scN), bc(scN > 0))
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
	addl("swap", swapEnc, bc(swapEnc != "plain"))

	// network security
	addh("network security")
	syncook := readSysctl("net.ipv4.tcp_syncookies")
	addl("tcp_syncookies", map[string]string{"0":"disabled","1":"SYN protection","?":"?"}[syncook], bc(syncook == "1"))
	rpfall := readSysctl("net.ipv4.conf.all.rp_filter")
	addl("rp_filter", map[string]string{"0":"disabled","1":"strict","2":"loose","?":"?"}[rpfall], bc(rpfall == "1"))
	redir := readSysctl("net.ipv4.conf.all.accept_redirects")
	addl("accept_redirects", map[string]string{"0":"disabled","1":"enabled","?":"?"}[redir], bc(redir == "0"))
	martians := readSysctl("net.ipv4.conf.all.log_martians")
	addl("log_martians", map[string]string{"0":"disabled","1":"enabled","?":"?"}[martians], bc(martians == "1"))
	ts := readSysctl("net.ipv4.tcp_timestamps")
	addl("tcp_timestamps", map[string]string{"0":"disabled","1":"leaks uptime","?":"?"}[ts], bc(ts == "0"))
	bpfjit := readSysctl("net.core.bpf_jit_harden")
	addl("bpf_jit_harden", map[string]string{"0":"disabled","1":"unprivileged","2":"all","?":"?"}[bpfjit], bc(bpfjit == "1" || bpfjit == "2"))
	sysrq := readSysctl("kernel.sysrq")
	addl("sysrq", map[string]string{"0":"disabled","1":"all keys","176":"safe subset","?":"?"}[sysrq], bc(sysrq != "1"))

	// network vulnerabilities
	addh("network vulnerabilities")
	srcr4 := readSysctl("net.ipv4.conf.all.accept_source_route")
	addl("source_route ipv4", map[string]string{"0":"blocked","1":"ENABLED","?":"?"}[srcr4], bc(srcr4 != "1"))
	srcr6 := readSysctl("net.ipv6.conf.all.accept_source_route")
	addl("source_route ipv6", map[string]string{"0":"blocked","-1":"blocked","1":"ENABLED","?":"?"}[srcr6], bc(srcr6 != "1"))
	sendRedir := readSysctl("net.ipv4.conf.all.send_redirects")
	addl("send_redirects", map[string]string{"0":"disabled","1":"ENABLED","?":"?"}[sendRedir], bc(sendRedir == "0"))
	bogus := readSysctl("net.ipv4.icmp_ignore_bogus_error_responses")
	addl("icmp_bogus_ignore", map[string]string{"0":"logging","1":"ignored","?":"?"}[bogus], bc(bogus == "1"))
	rfc1337 := readSysctl("net.ipv4.tcp_rfc1337")
	addl("tcp_rfc1337", map[string]string{"0":"vuln open","1":"protected","?":"?"}[rfc1337], bc(rfc1337 == "1"))
	tempaddr := readSysctl("net.ipv6.conf.all.use_tempaddr")
	addl("ipv6 privacy", map[string]string{"0":"disabled","1":"temp addr","2":"prefer temp","?":"?"}[tempaddr], bc(tempaddr == "2"))
	redir6 := readSysctl("net.ipv6.conf.all.accept_redirects")
	addl("ipv6 redirects", map[string]string{"0":"disabled","1":"ENABLED","?":"?"}[redir6], bc(redir6 == "0"))
	icmpRL := readSysctl("net.ipv4.icmp_ratelimit")
	addl("icmp_ratelimit", icmpRL+" ms", bc(icmpRL != "0"))
	ports := readListenPorts()
	addl("DNS port 53", map[bool]string{true:"LISTENING",false:"closed"}[checkPortOpen(ports, 53)], bc(!checkPortOpen(ports, 53)))
	addl("SMTP 25/587", map[bool]string{true:"LISTENING",false:"closed"}[checkPortOpen(ports, 25) || checkPortOpen(ports, 587)], bc(!checkPortOpen(ports, 25) && !checkPortOpen(ports, 587)))
	udpN := countUDPListen()
	addl("UDP sockets", fmt.Sprintf("%d active", udpN), bc(udpN <= 10))

	// SSH hardening
	addh("SSH hardening")
	if _, err := os.Stat("/etc/ssh/sshd_config"); err != nil {
		add(ColLine{Text: "  sshd not found", C: inf, Dim: true})
	} else {
		sshCfg := readSSHConfig()
		sshChk := func(key, goodVal, label string) {
			v, exists := sshCfg[strings.ToLower(key)]
			if !exists { addl(label, "n/a (default)", ok); return }
			addl(label, v, bc(strings.ToLower(v) == goodVal))
		}
		sshChk("PermitRootLogin", "no", "PermitRootLogin")
		sshChk("PasswordAuthentication", "no", "PasswordAuth")
		sshChk("X11Forwarding", "no", "X11Forwarding")
		sshChk("PermitEmptyPasswords", "no", "PermitEmptyPwd")
		sshChk("Protocol", "2", "Protocol")
		if v, exists := sshCfg["maxauthtries"]; exists {
			n, err2 := strconv.Atoi(v)
			addl("MaxAuthTries", v, bc(err2 == nil && n <= 4))
		} else {
			addl("MaxAuthTries", "n/a (default)", ok)
		}
	}

	// security tools
	addh("security tools")
	secTools := checkSecTools()
	for _, tool := range []string{"lynis", "rkhunter", "chkrootkit", "aide", "clamscan", "debsums", "tiger"} {
		inst := secTools[tool]
		note := "installed"
		if !inst { note = "not found" }
		if tool == "lynis" && inst {
			if score := lynisScore(); score != "" { note = "installed  score:" + score }
		}
		addl(tool, note, bc(inst))
	}

	// listening ports
	addh("listening ports")
	if len(ports) == 0 {
		add(ColLine{Text: "  none", C: inf, Dim: true})
	} else {
		line := " "
		for _, p := range ports {
			entry := fmt.Sprintf(" %s:%d", p.Proto, p.Port)
			if len([]rune(line+entry)) > 36 {
				add(ColLine{Text: line, C: t.NET})
				line = " "
			}
			line += entry
		}
		if line != " " { add(ColLine{Text: line, C: t.NET}) }
	}

	// established connections
	addh("connections")
	conns := readEstablished()
	ext := 0
	for _, c := range conns { if !isPrivateIP(c.Remote) { ext++ } }
	addl("established", fmt.Sprintf("total:%d  external:%d", len(conns), ext), bc(ext == 0))
	if !ui.Anon {
		shown := 0
		for _, c := range conns {
			if isPrivateIP(c.Remote) { continue }
			if shown >= 6 { add(ColLine{Text: fmt.Sprintf("   ... +%d more", ext-shown), C: warn}); break }
			add(ColLine{Text: "   → " + c.Remote, C: warn})
			shown++
		}
	}

	// users & access
	addh("users & access")
	totalU, loginU := countShellUsers()
	addl("shell users", fmt.Sprintf("total:%d  login:%d", totalU, loginU), inf)
	sshKeys := checkSSHAuthKeys()
	sshNote := "none"
	if len(sshKeys) > 0 { sshNote = strings.Join(sshKeys, " ") }
	addl("authorized_keys", sshNote, inf)
	if ui.Anon {
		addl("logged in", "[ANON]", inf)
	} else {
		users := readLoggedUsers()
		if len(users) == 0 {
			addl("logged in", "none", inf)
		} else {
			addl("logged in", fmt.Sprintf("%d sessions", len(users)), inf)
			for _, u := range users { add(ColLine{Text: "   " + u, C: inf}) }
		}
	}

	// dynamic column count
	nCols := 1
	if cols >= 140 { nCols = 3 } else if cols >= 80 { nCols = 2 }

	// split lines into nCols columns (balanced)
	total := len(lines)
	perCol := (total + nCols - 1) / nCols
	colData := make([][]ColLine, nCols)
	for i := 0; i < nCols; i++ {
		start := i * perCol
		end := start + perCol
		if end > total { end = total }
		if start < total { colData[i] = lines[start:end] }
	}

	colW := cols / nCols
	widths := make([]int, nCols)
	for i := range widths { widths[i] = colW }
	widths[nCols-1] = cols - colW*(nCols-1)

	// render — no dividers
	displayRows := rows - 2
	maxScroll := max(0, perCol-displayRows)
	if ui.SecScroll > maxScroll { ui.SecScroll = maxScroll }

	for row := 0; row < displayRows; row++ {
		buf.WriteString(pos(row, 0))
		for ci, col := range colData {
			w := widths[ci]
			idx := ui.SecScroll + row
			var attr, text string
			if idx < len(col) {
				l := col[idx]
				runes := []rune(l.Text)
				if len(runes) > w { runes = runes[:w] }
				text = string(runes) + strings.Repeat(" ", max(0, w-len(runes)))
				attr = ansiCol(l.C)
				if l.Bold { attr = BOLD + attr }
				if l.Dim  { attr = DIM  + attr }
			} else {
				text = strings.Repeat(" ", w)
			}
			buf.WriteString(attr + text + RESET)
		}
		buf.WriteString(CLEOL)
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
