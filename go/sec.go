package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

func readSysctl(key string) string {
	v, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(v))
}

func readListenPorts() []int {
	seen := map[int]bool{}
	var out []int
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
			if !seen[port] {
				seen[port] = true
				out = append(out, port)
			}
		}
	}
	sort.Ints(out)
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

func readCPUVulns() [][2]string {
	entries, err := os.ReadDir("/sys/devices/system/cpu/vulnerabilities")
	if err != nil {
		return nil
	}
	var out [][2]string
	for _, e := range entries {
		v, err := os.ReadFile("/sys/devices/system/cpu/vulnerabilities/" + e.Name())
		if err != nil {
			continue
		}
		out = append(out, [2]string{e.Name(), strings.TrimSpace(string(v))})
	}
	return out
}

func readSecureBoot() string {
	// try mokutil first
	out := runCmd(2000000000, "mokutil", "--sb-state")
	if strings.Contains(out, "enabled") {
		return "enabled"
	}
	if strings.Contains(out, "disabled") {
		return "disabled"
	}
	// check efi variable
	entries, err := os.ReadDir("/sys/firmware/efi/efivars")
	if err != nil {
		return "n/a (no EFI)"
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "SecureBoot-") {
			data, err := os.ReadFile("/sys/firmware/efi/efivars/" + e.Name())
			if err == nil && len(data) >= 5 {
				if data[4] == 1 {
					return "enabled"
				}
				return "disabled"
			}
		}
	}
	return "unknown"
}

func readKernelLockdown() string {
	v, err := os.ReadFile("/sys/kernel/security/lockdown")
	if err != nil {
		return "none"
	}
	s := strings.TrimSpace(string(v))
	// format: "none [integrity] confidentiality" — extract bracketed
	if i := strings.Index(s, "["); i >= 0 {
		if j := strings.Index(s[i:], "]"); j >= 0 {
			return s[i+1 : i+j]
		}
	}
	return s
}

func drawSEC(buf *strings.Builder, rows, cols int, ss *SysState, ui *UI, t *Theme) {
	hdr := clampStr(" SEC"+strings.Repeat("─", max(0, cols-4)), cols)
	buf.WriteString(pos(0, 0))
	buf.WriteString(ansiCol(t.HDR) + BOLD + hdr + RESET + CLEOL)

	ok := ansiCol(t.DISK) + BOLD + "OK  " + RESET
	warn := ansiCol(t.WARN) + BOLD + "WARN" + RESET
	part := ansiCol(t.RAM) + BOLD + "PART" + RESET
	dim := DIM + ansiCol(t.USB)
	hc := ansiCol(t.HDR) + BOLD

	ss.mu.RLock()
	vms := ss.VMs
	ss.mu.RUnlock()

	// build all lines into a slice, then render with scroll
	var lines []string
	add := func(s string) { lines = append(lines, s) }
	blank := func() { add("") }

	sctl := func(key string) string { return readSysctl(key) }
	boolOK := func(v string, goodVals ...string) string {
		for _, g := range goodVals {
			if v == g {
				return ok
			}
		}
		return warn
	}

	// ── kernel hardening ─────────────────────────────────────────────────────
	add(hc + " ── kernel hardening" + RESET)

	aslr := sctl("kernel.randomize_va_space")
	aslrS := warn
	if aslr == "2" {
		aslrS = ok
	} else if aslr == "1" {
		aslrS = part
	}
	aslrDesc := map[string]string{"0": "disabled", "1": "conservative", "2": "full"}[aslr]
	add(fmt.Sprintf("  %s ASLR                    %s%s%s  (%s)", aslrS, dim, aslrDesc, RESET, aslr))

	kptr := sctl("kernel.kptr_restrict")
	kptrDesc := map[string]string{"0": "kernel ptrs exposed", "1": "restricted (non-root)", "2": "hidden from all"}[kptr]
	add(fmt.Sprintf("  %s kptr_restrict            %s%s%s  (%s)", boolOK(kptr, "1", "2"), dim, kptrDesc, RESET, kptr))

	dmesg := sctl("kernel.dmesg_restrict")
	add(fmt.Sprintf("  %s dmesg_restrict           %skernel log %s%s  (%s)", boolOK(dmesg, "1"), dim,
		map[string]string{"0": "world-readable", "1": "root only"}[dmesg], RESET, dmesg))

	perf := sctl("kernel.perf_event_paranoid")
	perfS := ok
	if perf == "-1" || perf == "0" {
		perfS = warn
	}
	add(fmt.Sprintf("  %s perf_event_paranoid      %slevel %s%s", perfS, dim, perf, RESET))

	add(fmt.Sprintf("  %s suid_dumpable            %s%s%s  (%s)", boolOK(sctl("fs.suid_dumpable"), "0"), dim,
		map[string]string{"0": "disabled", "1": "enabled", "2": "suidsafe"}[sctl("fs.suid_dumpable")], RESET, sctl("fs.suid_dumpable")))

	bpf := sctl("kernel.unprivileged_bpf_disabled")
	add(fmt.Sprintf("  %s unprivileged_bpf         %s%s%s  (%s)", boolOK(bpf, "1", "2"), dim,
		map[string]string{"0": "allowed", "1": "disabled", "2": "admin only", "?": "n/a"}[bpf], RESET, bpf))

	userns := sctl("kernel.unprivileged_userns_clone")
	usernsS := boolOK(userns, "0")
	if userns == "?" {
		usernsS = ok
	}
	add(fmt.Sprintf("  %s unprivileged_userns      %s%s%s  (%s)", usernsS, dim,
		map[string]string{"0": "disabled", "1": "allowed", "?": "n/a"}[userns], RESET, userns))

	ptrace := sctl("kernel.yama.ptrace_scope")
	ptraceDesc := map[string]string{"0": "unrestricted", "1": "parent only", "2": "admin only", "3": "disabled"}[ptrace]
	if ptraceDesc == "" {
		ptraceDesc = ptrace
	}
	add(fmt.Sprintf("  %s ptrace_scope             %s%s%s  (%s)", boolOK(ptrace, "1", "2", "3"), dim, ptraceDesc, RESET, ptrace))

	modules := sctl("kernel.modules_disabled")
	add(fmt.Sprintf("  %s modules_disabled         %s%s%s", boolOK(modules, "1"), dim,
		map[string]string{"0": "modules loadable", "1": "loading locked", "?": "n/a"}[modules], RESET))

	execshield := sctl("kernel.exec-shield")
	if execshield != "?" {
		add(fmt.Sprintf("  %s exec-shield             %s%s%s  (%s)", boolOK(execshield, "1", "2"), dim, execshield, RESET, execshield))
	}

	blank()

	// ── network hardening ─────────────────────────────────────────────────────
	add(hc + " ── network hardening" + RESET)

	ipfwd := sctl("net.ipv4.ip_forward")
	add(fmt.Sprintf("  %s ip_forward               %s%s%s  (%s)", boolOK(ipfwd, "0"), dim,
		map[string]string{"0": "disabled (good)", "1": "enabled (router mode)"}[ipfwd], RESET, ipfwd))

	syncook := sctl("net.ipv4.tcp_syncookies")
	add(fmt.Sprintf("  %s tcp_syncookies           %s%s%s  (%s)", boolOK(syncook, "1"), dim,
		map[string]string{"0": "disabled", "1": "enabled (SYN flood protection)"}[syncook], RESET, syncook))

	rpfall := sctl("net.ipv4.conf.all.rp_filter")
	add(fmt.Sprintf("  %s rp_filter (all)          %s%s%s  (%s)", boolOK(rpfall, "1"), dim,
		map[string]string{"0": "disabled", "1": "strict", "2": "loose"}[rpfall], RESET, rpfall))

	redir := sctl("net.ipv4.conf.all.accept_redirects")
	add(fmt.Sprintf("  %s accept_redirects (all)   %s%s%s  (%s)", boolOK(redir, "0"), dim,
		map[string]string{"0": "disabled (safe)", "1": "enabled"}[redir], RESET, redir))

	srcroute := sctl("net.ipv4.conf.all.accept_source_route")
	add(fmt.Sprintf("  %s accept_source_route      %s%s%s  (%s)", boolOK(srcroute, "0"), dim,
		map[string]string{"0": "disabled (safe)", "1": "enabled"}[srcroute], RESET, srcroute))

	martians := sctl("net.ipv4.conf.all.log_martians")
	add(fmt.Sprintf("  %s log_martians             %s%s%s  (%s)", boolOK(martians, "1"), dim,
		map[string]string{"0": "disabled", "1": "enabled"}[martians], RESET, martians))

	ts := sctl("net.ipv4.tcp_timestamps")
	add(fmt.Sprintf("  %s tcp_timestamps           %s%s%s  (%s)", boolOK(ts, "0"), dim,
		map[string]string{"0": "disabled", "1": "enabled (leaks uptime)"}[ts], RESET, ts))

	icmpbcast := sctl("net.ipv4.icmp_echo_ignore_broadcasts")
	add(fmt.Sprintf("  %s icmp_echo_ignore_bcast   %s%s%s  (%s)", boolOK(icmpbcast, "1"), dim,
		map[string]string{"0": "responds", "1": "ignores (smurf protection)"}[icmpbcast], RESET, icmpbcast))

	blank()

	// ── MAC / firewall / boot ─────────────────────────────────────────────────
	add(hc + " ── access control & boot security" + RESET)

	aaS := warn
	if vms.AppArmor {
		aaS = ok
	}
	add(fmt.Sprintf("  %s AppArmor                %s%s%s", aaS, dim, map[bool]string{true: "active", false: "inactive"}[vms.AppArmor], RESET))

	seS := warn
	if vms.SELinux {
		seS = ok
	}
	add(fmt.Sprintf("  %s SELinux                 %s%s%s", seS, dim, map[bool]string{true: "enforcing", false: "inactive"}[vms.SELinux], RESET))

	fwS := warn
	fw := vms.Firewall
	if fw != "" {
		fwS = ok
	} else {
		fw = "none detected"
	}
	add(fmt.Sprintf("  %s Firewall                %s%s%s", fwS, dim, fw, RESET))

	swapEnc := "?"
	if raw, err := os.ReadFile("/proc/swaps"); err == nil {
		body := string(raw)
		if strings.Contains(body, "dm-") || strings.Contains(body, "zram") {
			swapEnc = "encrypted/zram"
		} else if strings.Count(body, "\n") > 1 {
			swapEnc = "plain (unencrypted)"
		} else {
			swapEnc = "none"
		}
	}
	swapS := ok
	if swapEnc == "plain (unencrypted)" {
		swapS = warn
	}
	add(fmt.Sprintf("  %s Swap                    %s%s%s", swapS, dim, swapEnc, RESET))

	sb := readSecureBoot()
	sbS := boolOK(sb, "enabled")
	add(fmt.Sprintf("  %s Secure Boot             %s%s%s", sbS, dim, sb, RESET))

	lockdown := readKernelLockdown()
	lockdownS := warn
	if lockdown == "integrity" || lockdown == "confidentiality" {
		lockdownS = ok
	} else if lockdown == "none" {
		lockdownS = warn
	}
	add(fmt.Sprintf("  %s Kernel lockdown         %s%s%s", lockdownS, dim, lockdown, RESET))

	blank()

	// ── CPU vulnerabilities ───────────────────────────────────────────────────
	add(hc + " ── CPU vulnerabilities" + RESET)
	vulns := readCPUVulns()
	if len(vulns) == 0 {
		add(dim + "  (not available)" + RESET)
	} else {
		for _, v := range vulns {
			name := v[0]
			val := v[1]
			isOK := strings.HasPrefix(val, "Not affected") || strings.HasPrefix(val, "Mitigation")
			s := warn
			if isOK {
				s = ok
			}
			short := val
			if len(short) > cols-30 && cols > 40 {
				short = short[:cols-30] + "…"
			}
			add(fmt.Sprintf("  %s %-22s %s%s%s", s, name, dim, short, RESET))
		}
	}

	blank()

	// ── listening ports ───────────────────────────────────────────────────────
	add(hc + " ── listening ports" + RESET)
	ports := readListenPorts()
	if len(ports) == 0 {
		add(dim + "  (none)" + RESET)
	} else {
		line := "  "
		for _, p := range ports {
			token := fmt.Sprintf("%s%d%s  ", ansiCol(t.NET), p, RESET)
			if len(line) > cols-16 {
				add(line)
				line = "  "
			}
			line += token
		}
		if line != "  " {
			add(line)
		}
	}

	blank()

	// ── logged-in users ───────────────────────────────────────────────────────
	add(hc + " ── logged-in users" + RESET)
	if ui.Anon {
		add(dim + "  [ANON]" + RESET)
	} else {
		users := readLoggedUsers()
		if len(users) == 0 {
			add(dim + "  (none / who unavailable)" + RESET)
		} else {
			for _, u := range users {
				add("  " + u)
			}
		}
	}

	// ── render with scroll ───────────────────────────────────────────────────
	avail := rows - 2
	if ui.SecScroll > len(lines)-avail {
		ui.SecScroll = max(0, len(lines)-avail)
	}
	if ui.SecScroll < 0 {
		ui.SecScroll = 0
	}

	for i := 0; i < avail; i++ {
		buf.WriteString(pos(1+i, 0))
		idx := ui.SecScroll + i
		if idx < len(lines) {
			buf.WriteString(clampVisual(lines[idx], cols) + CLEOL)
		} else {
			buf.WriteString(CLEOL)
		}
	}

	drawStatusBar(buf, rows, cols, ui, ui.Interval, ss, t)
}
