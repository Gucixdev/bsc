package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func fmtKB(kb int64) string {
	if kb >= 1<<20 {
		return fmt.Sprintf("%dG", kb>>20)
	}
	if kb >= 1<<10 {
		return fmt.Sprintf("%dM", kb>>10)
	}
	return fmt.Sprintf("%dK", kb)
}

// disasmAtRIP — reads 96 bytes from /proc/PID/mem at rip, disassembles via ndisasm/objdump/hex fallback
func disasmAtRIP(pid int, ripHex string, maxLines int) []string {
	rip, err := strconv.ParseInt(strings.TrimPrefix(ripHex, "0x"), 16, 64)
	if err != nil {
		return nil
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return []string{"  (cannot read mem — need root)"}
	}
	defer f.Close()
	raw := make([]byte, 96)
	n, _ := f.ReadAt(raw, rip)
	bs := raw[:n]
	if n == 0 {
		return []string{"  (no data at rip)"}
	}

	if _, err := exec.LookPath("ndisasm"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		cmd := exec.CommandContext(ctx, "ndisasm", "-b", "64", fmt.Sprintf("-o0x%016x", rip), "-")
		cmd.Stdin = bytes.NewReader(bs)
		if out, err := cmd.Output(); err == nil {
			var lines []string
			for _, l := range strings.Split(string(out), "\n") {
				if l != "" {
					lines = append(lines, "  "+l)
				}
			}
			if len(lines) > maxLines {
				lines = lines[:maxLines]
			}
			return lines
		}
	}

	if _, err := exec.LookPath("objdump"); err == nil {
		tmp, err := os.CreateTemp("", "bsc_asm")
		if err == nil {
			tmp.Write(bs)
			tmp.Close()
			defer os.Remove(tmp.Name())
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			defer cancel()
			out, err := exec.CommandContext(ctx, "objdump", "-b", "binary", "-m", "i386:x86-64",
				"-M", "intel", "-D", fmt.Sprintf("--adjust-vma=0x%x", rip), tmp.Name()).Output()
			if err == nil {
				var lines []string
				for _, l := range strings.Split(string(out), "\n") {
					ls := strings.TrimSpace(l)
					if ls == "" || strings.HasSuffix(ls, ":") {
						continue
					}
					if strings.Contains(ls, ":") && ls[0] != 'D' && ls[0] != '/' {
						lines = append(lines, "  "+ls)
					}
				}
				if len(lines) > maxLines {
					lines = lines[:maxLines]
				}
				return lines
			}
		}
	}

	// raw hex fallback
	var lines []string
	for i := 0; i < len(bs) && i < 48; i += 8 {
		end := i + 8
		if end > len(bs) {
			end = len(bs)
		}
		var parts []string
		for _, b := range bs[i:end] {
			parts = append(parts, fmt.Sprintf("%02x", b))
		}
		lines = append(lines, fmt.Sprintf("  0x%016x  %s", rip+int64(i), strings.Join(parts, " ")))
	}
	return lines
}

func runCmd(d time.Duration, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	out, _ := exec.CommandContext(ctx, name, args...).Output()
	return strings.TrimSpace(string(out))
}

// readAudio — ALSA native + PipeWire + PulseAudio + JACK (TTL in collectAll)
func readAudio() []AudioServer {
	var servers []AudioServer

	// ALSA — always, zero tools
	alsa := AudioServer{Name: "ALSA"}
	if entries, err := os.ReadDir("/proc/asound"); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), "card") {
				alsa.Active = true
				alsa.Lines = append(alsa.Lines, e.Name())
			}
		}
	}
	servers = append(servers, alsa)

	// PipeWire
	pw := AudioServer{Name: "PipeWire"}
	pwOut := runCmd(3*time.Second, "pw-dump")
	if pwOut != "" {
		pw.Active = true
		// count audio nodes
		count := strings.Count(pwOut, `"type":"PipeWire:Interface:Node"`)
		pw.Lines = append(pw.Lines, fmt.Sprintf("nodes:%d", count))
	} else {
		// fallback wpctl
		vol := runCmd(time.Second, "wpctl", "get-volume", "@DEFAULT_AUDIO_SINK@")
		if vol != "" {
			pw.Active = true
			pw.Lines = append(pw.Lines, vol)
		}
	}
	servers = append(servers, pw)

	// PulseAudio
	pa := AudioServer{Name: "PulseAudio"}
	paInfo := runCmd(2*time.Second, "pactl", "info")
	if paInfo != "" {
		pa.Active = true
		vol := runCmd(time.Second, "pactl", "get-sink-volume", "@DEFAULT_SINK@")
		if vol != "" {
			pa.Lines = append(pa.Lines, vol)
		}
	}
	servers = append(servers, pa)

	// JACK
	jack := AudioServer{Name: "JACK"}
	jackOut := runCmd(time.Second, "jack_lsp")
	if jackOut != "" {
		jack.Active = true
		jack.Lines = append(jack.Lines, fmt.Sprintf("ports:%d", len(strings.Split(jackOut, "\n"))))
	}
	servers = append(servers, jack)

	return servers
}

// readUSB — /sys/bus/usb/devices product + manufacturer
func readUSB() []string {
	seen := map[string]bool{}
	var result []string
	entries, _ := os.ReadDir("/sys/bus/usb/devices")
	for _, e := range entries {
		base := "/sys/bus/usb/devices/" + e.Name()
		prod, _ := os.ReadFile(base + "/product")
		mfr, _ := os.ReadFile(base + "/manufacturer")
		p := strings.TrimSpace(string(prod))
		m := strings.TrimSpace(string(mfr))
		if p == "" {
			continue
		}
		label := p
		if m != "" && m != p {
			label = m + " " + p
		}
		if !seen[label] {
			seen[label] = true
			result = append(result, label)
		}
	}
	return result
}

// hasBin — check if binary is in PATH
func hasBin(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// procRssKB — RSS memory from /proc/PID/status
func procRssKB(pid string) int {
	data, _ := os.ReadFile("/proc/" + pid + "/status")
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				v, _ := strconv.Atoi(fields[1])
				return v
			}
		}
	}
	return 0
}

// readVMs — QEMU/docker/podman/VBox/VMware scan (TTL in collectAll)
func readVMs() VMStat {
	v := VMStat{}

	// KVM
	if _, err := os.Stat("/dev/kvm"); err == nil {
		v.KVMExists = true
	}
	// CPU vendor from cpuinfo
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "flags") || strings.HasPrefix(line, "Features") {
				if strings.Contains(line, "vmx") {
					v.KVMVendor = "Intel"
				} else if strings.Contains(line, "svm") {
					v.KVMVendor = "AMD"
				}
				break
			}
		}
	}

	v.QEMUInst = hasBin("qemu-system-x86_64")
	v.VBoxInst = hasBin("VBoxHeadless") || hasBin("VBoxManage")
	v.VMwareInst = hasBin("vmware-vmx") || hasBin("vmrun")
	v.DockerInst = hasBin("docker")
	v.PodmanInst = hasBin("podman")
	v.BwrapInst = hasBin("bwrap")

	// scan /proc for QEMU, VBox, VMware running instances
	procs, _ := os.ReadDir("/proc")
	for _, e := range procs {
		pid := e.Name()
		if pid[0] < '0' || pid[0] > '9' {
			continue
		}
		cmdlineB, _ := os.ReadFile("/proc/" + pid + "/cmdline")
		cmdline := string(cmdlineB)
		args := strings.Split(cmdline, "\x00")

		if strings.Contains(cmdline, "qemu-system") {
			name := pid // fallback: PID
			for i, a := range args {
				if a == "-name" && i+1 < len(args) {
					n := args[i+1]
					// qemu -name "guest=foo,..." → extract "foo"
					if idx := strings.Index(n, "="); idx >= 0 {
						n = n[idx+1:]
					}
					if idx := strings.Index(n, ","); idx >= 0 {
						n = n[:idx]
					}
					name = n
					break
				}
			}
			v.QEMUVMs = append(v.QEMUVMs, VMInfo{
				Name:  name,
				Status: "run",
				RssKB: procRssKB(pid),
			})
		}

		comm, _ := os.ReadFile("/proc/" + pid + "/comm")
		cs := strings.TrimSpace(string(comm))
		if strings.Contains(cs, "VBoxHeadless") {
			// try to get VM name from cmdline
			name := pid
			for i, a := range args {
				if (a == "--startvm" || a == "-startvm") && i+1 < len(args) {
					name = args[i+1]
					break
				}
			}
			v.VBoxVMs = append(v.VBoxVMs, VMInfo{Name: name, Status: "run"})
		}
		if strings.Contains(cs, "vmware-vmx") {
			// vmx file path is last meaningful arg
			name := pid
			for i := len(args) - 1; i >= 0; i-- {
				if strings.HasSuffix(args[i], ".vmx") {
					name = strings.TrimSuffix(filepath.Base(args[i]), ".vmx")
					break
				}
			}
			v.VMwareVMs = append(v.VMwareVMs, VMInfo{Name: name, Status: "run"})
		}

		if strings.Contains(cs, "bwrap") {
			v.BwrapCount++
		}
	}

	// docker containers
	if v.DockerInst {
		dout := runCmd(2*time.Second, "docker", "ps", "-a",
			"--format", "{{.Names}}\t{{.Status}}\t{{.ID}}")
		for _, line := range strings.Split(dout, "\n") {
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "\t", 3)
			if len(parts) < 2 {
				continue
			}
			st := "stop"
			if strings.HasPrefix(parts[1], "Up") {
				st = "run"
			} else if strings.HasPrefix(parts[1], "Paused") {
				st = "pause"
			}
			id := ""
			if len(parts) >= 3 && len(parts[2]) >= 8 {
				id = parts[2][:8]
			}
			v.DockerVMs = append(v.DockerVMs, VMInfo{Name: parts[0], Status: st, ID: id})
		}
	}

	// podman containers
	if v.PodmanInst {
		pout := runCmd(2*time.Second, "podman", "ps", "-a",
			"--format", "{{.Names}}\t{{.Status}}\t{{.ID}}")
		for _, line := range strings.Split(pout, "\n") {
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "\t", 3)
			if len(parts) < 2 {
				continue
			}
			st := "stop"
			if strings.HasPrefix(parts[1], "Up") || strings.HasPrefix(parts[1], "running") {
				st = "run"
			} else if strings.HasPrefix(parts[1], "Paused") {
				st = "pause"
			}
			id := ""
			if len(parts) >= 3 && len(parts[2]) >= 8 {
				id = parts[2][:8]
			}
			v.PodmanVMs = append(v.PodmanVMs, VMInfo{Name: parts[0], Status: st, ID: id})
		}
	}

	// firewall
	if _, err := os.Stat("/proc/net/nf_conntrack_stat"); err == nil {
		v.Firewall = "iptables/nftables"
	}
	if hasBin("ufw") {
		if ufw := runCmd(time.Second, "ufw", "status"); strings.Contains(ufw, "active") {
			v.Firewall = "ufw"
		}
	}

	// sandbox / security
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil {
		v.AppArmor = true
	}
	if data, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		v.SELinux = strings.TrimSpace(string(data)) == "1"
	}

	return v
}

// readHooks — ~/.config/bsc/hooks/* exec (TTL in collectAll)
func readHooks() []string {
	dir := os.Getenv("HOME") + "/.config/bsc/hooks"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var result []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		out := runCmd(4*time.Second, dir+"/"+e.Name())
		if out != "" {
			result = append(result, out)
		}
	}
	return result
}

// readBattery — /sys/class/power_supply
func readBattery() BattInfo {
	entries, _ := os.ReadDir("/sys/class/power_supply")
	for _, e := range entries {
		base := "/sys/class/power_supply/" + e.Name()
		typ, _ := os.ReadFile(base + "/type")
		if strings.TrimSpace(string(typ)) != "Battery" {
			continue
		}
		b := BattInfo{}
		if v, err := os.ReadFile(base + "/capacity"); err == nil {
			b.Pct, _ = strconv.Atoi(strings.TrimSpace(string(v)))
		}
		if v, err := os.ReadFile(base + "/status"); err == nil {
			s := strings.TrimSpace(string(v))
			b.Charging = s == "Charging"
			b.Full = s == "Full"
		}
		// power in µW
		if v, err := os.ReadFile(base + "/power_now"); err == nil {
			uw, _ := strconv.ParseFloat(strings.TrimSpace(string(v)), 64)
			b.Watts = uw / 1e6
		} else {
			// current_now (µA) * voltage_now (µV) / 1e12
			ia, _ := os.ReadFile(base + "/current_now")
			va, _ := os.ReadFile(base + "/voltage_now")
			if len(ia) > 0 && len(va) > 0 {
				iuA, _ := strconv.ParseFloat(strings.TrimSpace(string(ia)), 64)
				vuV, _ := strconv.ParseFloat(strings.TrimSpace(string(va)), 64)
				b.Watts = iuA * vuV / 1e12
			}
		}
		return b
	}
	return BattInfo{}
}

// readUptime — /proc/uptime → seconds
func readUptime() int64 {
	v, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(v))
	if len(fields) == 0 {
		return 0
	}
	f, _ := strconv.ParseFloat(fields[0], 64)
	return int64(f)
}
