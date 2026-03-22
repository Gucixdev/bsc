# bsc — bullshit control. basement control. better control.

Single-file Go TUI. No external deps — stdlib only. Static binary, zero runtime deps.

```
./bsc
```

## tabs

| key | tab |
|-----|-----|
| `1` | OVW — overview + process list |
| `2` | DEV — kernel internals |
| `3` | SEC — security & hardening |
| `4` | HEX — raw hex dump |
| `Tab` | cycle |

## OVW columns

**CPU** — per-core %, freq, temp, turbo count, throttle, load avg, RAPL watts

**RAM** — ram / swap / zram used/total%, hugepages, dirty, writeback. GPU vram if nvidia/amd.

**DISK** — per-device read/write MB/s, iops, util%, queue depth, scheduler. SMART health inline.

**NET** — per-interface rx/tx KB/s, ip, mask, ipv6, mac, speed, wifi SSID + signal, bluetooth

**GPU** — nvidia (nvidia-smi): vram, util%, temp, power, fan, clock. AMD (ROCm/hwmon) same.

**VMs** — KVM /dev/kvm, QEMU processes, Docker/Podman containers (all states), VirtualBox, VMware, Proxmox VMs+LXC. Bubblewrap sandbox count, firewall, AppArmor/SELinux/seccomp.

**Audio** — all detected servers simultaneously: ALSA (streams, hw_params), PipeWire (per-channel volumes, format, rate), WirePlumber, PulseAudio/pipewire-pulse (vol, mic, sinks), JACK (ports). Green if running, dim if installed but inactive.

**Hooks** — run any executable from `~/.config/bsc/hooks/` and show output live

**Procs** — sortable by cpu/mem, filter modes, search, SIGTERM/SIGKILL, detail panel (fds/maps/threads/cgroup/namespaces/oom)

## DEV columns

- kernel version, cmdline, boot params
- sysctl tunables (vm/net/kernel)
- top IRQs with delta counts
- CPU flags — full x86_64 set (~80 flags), present=green missing=dim
- syscall trace: 1-3 cores side by side (width≥150→3col, ≥80→2col), `←→` to shift window
- registers (SP/PC) + disassembly at PC when process is in syscall

## SEC tab

Two-column panel layout — scroll with `↑↓`.

**Left — kernel & rootkit**
- kernel hardening: ASLR, kptr_restrict, dmesg_restrict, perf_event_paranoid, ptrace_scope (Yama), suid_dumpable, unprivileged_bpf, unprivileged_userns_clone, kexec_load_disabled, protected_symlinks/hardlinks, ip_forward, modules_disabled, kernel lockdown
- kernel taint flags (all 18 bits)
- rootkit indicators: hidden proc delta, LD_PRELOAD injection, kallsyms address leak, raw sockets, unsigned/OOT modules, SUID/SGID binary count, /etc/ld.so.preload, core_pattern pipe, /tmp sticky bit, IMA policy

**Right — firewall, network, users**
- firewall & sandbox: AppArmor, SELinux, iptables/nftables, Firejail (installed + active sandboxes), seccomp filter process count, swap encryption
- network security: tcp_syncookies, rp_filter, accept_redirects, log_martians, tcp_timestamps, bpf_jit_harden, sysrq
- network vulnerabilities: source routing (ipv4/ipv6), send_redirects, icmp_bogus, tcp_rfc1337, IPv6 privacy extensions, IPv6 redirects, ICMP rate limit, open DNS/SMTP port detection, UDP socket count
- listening ports (all TCP)
- established connections (external IP list)
- users & access: shell users, SSH authorized_keys, logged-in sessions

## HEX tab

Three sources switchable with `w` (cycles MEM→DISK→NET):

| source | what |
|--------|------|
| **mem** | `/proc/PID/mem` — live process memory, region picker |
| **disk** | raw block device sector dump |
| **net** | captured packets (AF_PACKET), auto-tail or manual scroll |

Dynamic bytes-per-row fills full terminal width. Green = data, gray = zero, yellow = search match.

## keybinds

```
q        quit
+/-      interval ms
R        record to ~/.local/share/bsc/
a        anonymous mode (hides IPs, MACs, SSIDs, users, cmdlines)

OVW
↑↓       select process
←→       filter mode
Enter/v  process detail panel
d        jump to DEV tab
k / 9    SIGKILL
y / Y    yank PID / cmd
Space    mark process
f        freeze sort order
c / m    sort by cpu / mem
/        search

DEV
←→       shift core window
↑↓       scroll

SEC
↑↓       scroll

HEX
w        cycle source: mem → disk → net
↑↓       scroll
←→       select region / disk / iface
l        lock/unlock net autoscroll
/        search bytes
```

## install

```bash
bash scripts/bsc-cmd info
```

## theme

`~/.config/bsc/theme.json` — accepts `#RRGGBB` hex or xterm-256 integers.
Truecolor used automatically when terminal supports it (`COLORTERM=truecolor`):

```json
{
  "HDR":  "#ff8700",
  "CPU":  "#8700ff",
  "GPU":  "#00ff5f",
  "RAM":  "#ffd700",
  "ZRAM": "#af87ff",
  "DISK": "#00ff5f",
  "NET":  "#0087ff",
  "SEL":  "#ffff00",
  "USB":  "#8a8a8a",
  "MARK": "#ff8700",
  "WARN": "#ff0000"
}
```

## syscall trace

Uses **eBPF** (`bpftrace`) when available — needs `CAP_BPF` or root.
Falls back to `/proc/PID/syscall` polling at 10ms per core.
Run-length encoded: `futex(...) ×8492` shows how long a process sleeps.

## optional tools

Everything is optional — bsc degrades gracefully. Fallback chains below.

**GPU** (tried in order, first that works wins):
```
NVIDIA:  nvidia-smi → libnvidia-ml.so (ctypes, no binary) → /proc/driver/nvidia → /sys/class/hwmon
AMD:     rocm-smi   → /sys/class/hwmon/amdgpu + /sys/class/drm/*/gpu_busy_percent
Intel:   /sys/class/hwmon/i915
other:   /sys/class/hwmon/nouveau
```

**syscall trace** (tried in order):
```
bpftrace (eBPF, CAP_BPF/root) → perf trace --cpu N (perf_event_paranoid<=2) → /proc poll 10ms
```
shows 1-3 cores simultaneously depending on terminal width (≥150=3col ≥80=2col).
bpftrace captures all cores at once (system-wide, no per-core subprocess).
run-length encoded: `futex(...) ×8492` = process sleeping in that syscall.

**disassembly:**
```
ndisasm → objdump
```

**WiFi SSID** (tried in order, parallel):
```
iwgetid → iw dev info → iwconfig → wpa_cli → wpa_cli -p /var/run/wpa_supplicant → nmcli
```

**audio:**
```
ALSA:        /proc/asound + /proc/asound/*/pcm*/sub*/status (always, zero tools needed)
             hw_params: rate, format, channels, period, buffer — from running PCM streams
PipeWire:    pw-dump (per-channel vol, format, rate) + wpctl (vol control)
WirePlumber: wpctl
PulseAudio:  pactl (vol, mic, streams, sinks) — also works with pipewire-pulse
JACK:        jack_lsp (port count)
all servers shown simultaneously, green=running dim=installed-but-stopped
```

**containers / VMs:**
```
podman  docker  qm (Proxmox VM)  pct (Proxmox LXC)
QEMU/VirtualBox/VMware detected from /proc without any tools
```

**other:**
```
smartctl   — disk SMART health
sensors    — extra hwmon fallback
```

## platforms

Tested on Linux x86_64. Everything reads from `/proc`, `/sys`, and standard Linux tools.

### macOS / BSD
The core display logic is portable — pure ANSI, no curses.
What needs porting: `/proc` → `sysctl()` calls, RAPL → `powermetrics`,
disk stats → `IOKit`, network → `getifaddrs`.
PRs welcome.

### Windows
WSL2 runs bsc as-is (Linux `/proc` available inside the VM).
Native Windows would need a full data-collection rewrite (psutil or raw WinAPI).
PRs welcome.

## license

PIZZAWARE — do whatever you want. If it's useful, buy me a pizza.
