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
	PID   int
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
			if len(f) < 4 {
				continue
			}
			// state 0A = TCP_LISTEN
			if f[3] != "0A" {
				continue
			}
			// local_address field: hex IP:PORT
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

// readLoggedUsers — /proc/net/unix fallback; simpler: parse /var/run/utmp via `who`
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

func drawSEC(buf *strings.Builder, rows, cols int, ss *SysState, ui *UI, t *Theme) {
	hdr := clampStr(" SEC"+strings.Repeat("─", max(0, cols-4)), cols)
	buf.WriteString(pos(0, 0))
	buf.WriteString(ansiCol(t.HDR) + BOLD + hdr + RESET + CLEOL)

	row := 1
	write := func(s string) {
		if row >= rows-1 {
			return
		}
		buf.WriteString(pos(row, 0))
		buf.WriteString(clampVisual(s, cols) + CLEOL)
		row++
	}
	blank := func() { write("") }

	ok := ansiCol(t.DISK) + BOLD + "OK  " + RESET
	warn := ansiCol(t.WARN) + BOLD + "WARN" + RESET
	info := DIM + ansiCol(t.USB)
	hc := ansiCol(t.HDR) + BOLD

	ss.mu.RLock()
	vms := ss.VMs
	ss.mu.RUnlock()

	// ── Kernel hardening ──────────────────────────────────────────────────────
	write(hc + " ── kernel hardening" + RESET)

	aslr := readSysctl("kernel.randomize_va_space")
	aslrState := warn
	if aslr == "2" {
		aslrState = ok
	} else if aslr == "1" {
		aslrState = ansiCol(t.RAM) + BOLD + "PART" + RESET
	}
	write(fmt.Sprintf("  %s ASLR                   %s%s%s  (randomize_va_space=%s)", aslrState, info, aslrDesc(aslr), RESET, aslr))

	kptr := readSysctl("kernel.kptr_restrict")
	kptrState := warn
	if kptr != "0" {
		kptrState = ok
	}
	write(fmt.Sprintf("  %s kptr_restrict           %s%s%s  (%s)", kptrState, info, kptrDesc(kptr), RESET, kptr))

	dmesg := readSysctl("kernel.dmesg_restrict")
	dmesgState := warn
	if dmesg == "1" {
		dmesgState = ok
	}
	write(fmt.Sprintf("  %s dmesg_restrict          %skernel log %s%s  (%s)", dmesgState, info, map[string]string{"0": "readable by all", "1": "root only"}[dmesg], RESET, dmesg))

	perf := readSysctl("kernel.perf_event_paranoid")
	perfState := ok
	if perf == "-1" || perf == "0" {
		perfState = warn
	}
	write(fmt.Sprintf("  %s perf_event_paranoid     %slevel %s%s", perfState, info, perf, RESET))

	suid := readSysctl("fs.suid_dumpable")
	suidState := ok
	if suid != "0" {
		suidState = warn
	}
	write(fmt.Sprintf("  %s suid_dumpable           %s%s%s  (%s)", suidState, info, map[string]string{"0": "disabled", "1": "enabled", "2": "suidsafe"}[suid], RESET, suid))

	bpf := readSysctl("kernel.unprivileged_bpf_disabled")
	bpfState := warn
	if bpf == "1" || bpf == "2" {
		bpfState = ok
	}
	write(fmt.Sprintf("  %s unprivileged_bpf        %s%s%s  (%s)", bpfState, info, map[string]string{"0": "allowed", "1": "disabled", "2": "admin only"}[bpf], RESET, bpf))

	userns := readSysctl("kernel.unprivileged_userns_clone")
	usernsState := warn
	if userns == "0" {
		usernsState = ok
	}
	if userns == "?" {
		usernsState = ok // not all kernels have this
	}
	write(fmt.Sprintf("  %s unprivileged_userns     %s%s%s  (%s)", usernsState, info, map[string]string{"0": "disabled", "1": "allowed", "?": "n/a"}[userns], RESET, userns))

	blank()

	// ── MAC / firewall ────────────────────────────────────────────────────────
	write(hc + " ── mandatory access control & firewall" + RESET)

	aaState := warn
	if vms.AppArmor {
		aaState = ok
	}
	write(fmt.Sprintf("  %s AppArmor               %s%s%s", aaState, info, map[bool]string{true: "active", false: "inactive"}[vms.AppArmor], RESET))

	seState := warn
	if vms.SELinux {
		seState = ok
	}
	write(fmt.Sprintf("  %s SELinux                %s%s%s", seState, info, map[bool]string{true: "enforcing", false: "inactive"}[vms.SELinux], RESET))

	fwState := warn
	if vms.Firewall != "" {
		fwState = ok
	}
	fw := vms.Firewall
	if fw == "" {
		fw = "none detected"
	}
	write(fmt.Sprintf("  %s Firewall               %s%s%s", fwState, info, fw, RESET))

	// swap encrypt
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
	swapEncState := ok
	if swapEnc == "plain" {
		swapEncState = warn
	}
	write(fmt.Sprintf("  %s Swap                   %s%s%s", swapEncState, info, swapEnc, RESET))

	blank()

	// ── Listening ports ───────────────────────────────────────────────────────
	write(hc + " ── listening ports" + RESET)
	ports := readListenPorts()
	if len(ports) == 0 {
		write(info + "  (none)" + RESET)
	} else {
		line := "  "
		for i, p := range ports {
			if i > 0 {
				line += "  "
			}
			if len(line) > cols-12 {
				write(line)
				line = "  "
			}
			line += fmt.Sprintf("%s%s:%d%s", ansiCol(t.NET), p.Proto, p.Port, RESET)
		}
		if line != "  " {
			write(line)
		}
	}

	blank()

	// ── Logged-in users ───────────────────────────────────────────────────────
	write(hc + " ── logged-in users" + RESET)
	users := readLoggedUsers()
	if len(users) == 0 {
		write(info + "  (none / who unavailable)" + RESET)
	} else {
		for _, u := range users {
			write("  " + u)
			if row >= rows-2 {
				break
			}
		}
	}

	// clear remaining lines
	for row < rows-1 {
		buf.WriteString(pos(row, 0))
		buf.WriteString(CLEOL)
		row++
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
