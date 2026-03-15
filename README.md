# bsc — bullshit control. basement control. better control.

Single-file Python TUI. No deps beyond stdlib + curses.

```
python3 bsc
```

## tabs

| key | tab |
|-----|-----|
| `1` | OVW — overview + process list |
| `2` | DEV — kernel internals |
| `3` | HEX — raw hex dump |
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

## HEX tab

Three sources switchable with `m` / `d` / `n`:

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

OVW
↑↓       select process
←→       filter mode
Enter/v  process detail panel
d        jump to DEV
k/9      SIGTERM / SIGKILL
/        search
i/o      scroll net column

DEV
←→  h/l  switch cpu core
↑↓  i/o  scroll

HEX
m/d/n    source: mem / disk / net
↑↓       scroll
l        lock/unlock net autoscroll
/        search bytes
```

## install

```bash
bash install
# → ~/.local/bin/bsc
# → ~/.config/bsc/theme.json
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

## todo

### OVW
- process tree — PPID z `/proc/PID/status`; pstree-style, zero narzędzi
- ghost trace — martwy proc zostaje szary 5s; łapie transient procs
- zombie & D-state tracker — `/proc/PID/status` State=Z/D; licznik + lista
- top talkers — `/proc/net/tcp` + udp inode→PID; kolumna NET w liście procesów
- sparklines rx/tx — 30s ASCII historia (▁▂▃▄▅▆▇█) obok KB/s
- promiscuous mode warning — `/sys/class/net/*/flags` bit IFF_PROMISC (0x100)
- battery / UPS column — `/sys/class/power_supply`; charge%, health, current draw
- CAP column — `/proc/PID/status` CapEff bitmask; kolumna w liście procesów; highlight jeśli CAP_SYS_ADMIN/CAP_NET_RAW/CAP_SYS_PTRACE

### DEV
- MSR temp bezpośrednio — `/dev/cpu/N/msr` 0x19C (IA32_THERM_STATUS); bez sensors
- microcode version — `/sys/devices/system/cpu/cpu0/microcode/version`; Spectre/Meltdown status
- kernel taints & unsigned modules — `/proc/sys/kernel/tainted` bitmask + `/proc/modules` col4
- IPC / shared memory — `/proc/sysvipc/shm|sem|msg`; które PIDy są "sklejone"
- dynamic linker monitor — `/proc/PID/maps` filtr .so; failed open = brakująca biblioteka
- syscall copy shortcut — klawisz `c`; backend: OSC 52 → xclip → xsel → wl-copy (cascade); OSC 52 działa przez SSH — kopiuje do lokalnego schowka na laptopie bez dodatkowych narzędzi
- io_uring trace — eBPF przez surowy `bpf()` syscall (bez bcc/libbpf); ładowanie bajtkodu ręcznie; submissions obok syscall trace

### process detail panel (v)
- open files — `/proc/PID/fd` readlink; typ: file/socket/pipe/anon_inode
- connection map — `/proc/net/tcp{,6}` + udp; PROTO|LOCAL|REMOTE|STATE|SERVICE
- VMA visualization — `/proc/PID/maps` ASCII bar [Stack][Heap][Libs][Text][Shr]; enter→HEX jump
- capabilities decode — CapEff hex (już jest) → decode do nazw CAP_NET_ADMIN etc.
- resource limits — `/proc/PID/limits` (ulimits)

### nowa zakładka SEC
- reverse shell hunter — shell parent (/bin/sh|python) + aktywne gniazdo TCP
- suspicious raw sockets — AF_PACKET users z `/proc/net/packet`; ostrzeżenie jeśli != bsc
- entropy monitor + auto-kill — delta entropii zapisu na dysk przez inotify+stat(); spike > próg → SIGKILL procesu bez pytania; próg konfigurowalny w `~/.config/bsc/bsc.conf`; darmowy anti-ransomware
- SUID modified <24h — stat() na plikach z bitem SUID; alert przy świeżych
- DNS sniffer — AF_PACKET port 53 UDP; parse query name; log 5 ostatnich per iface
- bullshit level — klawisz `b`; lista z `~/.config/bsc/bullshit` (nazwa/glob per linia);
  wyświetla "BULLSHIT LEVEL [████░░░] 62%" + SIGTERM/SIGKILL z roota

### OVW — PWR (bez nowej zakładki, do istniejącej kolumny CPU/RAM)
- P-States / C-States — `/sys/devices/system/cpu/cpuN/cpuidle/stateN/`; które stany aktywne
- thermal zones full map — `/sys/class/thermal/thermal_zone*/temp` + type; VRM, NVMe, mostki
- PSI (Pressure Stall Information) — `/proc/pressure/{cpu,io,memory}`; `some` + `full` avg10/avg60; zastępuje load average jako miarę duszenia się systemu

### hardware / events
- USB/PCIe hotplug — poll `/sys/bus/usb/devices` + `/sys/bus/pci/devices`; nowe = highlight
- system events watchdog — próg CPU/mem/disk per proc → auto-start recording lub zrzut pamięci

### nowa zakładka LOG
- log kollator — czytaj `/dev/kmsg` (dmesg) równolegle z innymi źródłami; jeden strumień, jeden widok
- OOM killer alert — grep `kmsg` na "Out of memory: Killed"; **globalny overlay** widoczny z każdej zakładki (górna ramka, WARN_COLOR); PID + nazwa + RSS w chwili śmierci; klawisz `x` = dismiss
- USB/hardware events — nowe wpisy `kmsg` z prefixem `usb`/`input`/`block`; pokazuj UUID+FS nowego urządzenia
- log filter — klawisz `/`; regex w locie; WARN/ERR kolorowane WARN_COLOR

### nowa zakładka IO
- inotify file snooper — `inotify_init` + `inotify_add_watch /`; kolumny: PID | PROC | PATH | OP (WRITE/DELETE/RENAME)
  → detekcja śmieciarek w /tmp i procesów szpiegujących pliki użytkownika; bez inotifywait, czyste syscalle
- disk saturation map — `/proc/diskstats` util% per urządzenie; ASCII bar + await ms
- writeback stall monitor — `/proc/vmstat` pgwriteback; skok = aplikacje blokują się na flush

### graceful degradation (root vs user)
```
root                    → eBPF traces, /dev/kmsg, MSR, raw sockets, inotify /, SEC tab
CAP_NET_RAW             → DNS sniffer, packet capture
CAP_SYS_PTRACE          → open files per PID (/proc/PID/fd)
brak uprawnień (user)   → /proc stats, temp, /sys, OVW/DEV/NET readonly
```
bsc pokazuje aktywne możliwości przy starcie (1 linia statusu); nie crashuje — degraduje się cicho.

### cross-tab / misc
- Intel Arc GPU — `/sys/class/hwmon/xe`; util%/temp/vram
- Filesystem column — `/proc/mounts` + `statvfs()`; df-style, zero narzędzi
- CPU perf counters — IPC, cache-miss%, branch-miss% via `perf_event_open` syscall
- NUMA topology — `/sys/devices/system/node`; node/distance map
- cgroups v2 tree — hierarchy + per-cgroup CPU/mem limits
- RSS timeline — historia wzrostu RSS per proc; sparkline w panelu detalu
- ARM / RISC-V — arch-neutral fallback zamiast x86 MSR/RAPL

## platforms

Tested on Linux x86_64. Everything reads from `/proc`, `/sys`, and standard Linux tools.

### macOS / BSD
The core display logic is portable — curses works fine.
What needs porting: `/proc` → `sysctl()` calls, RAPL → `powermetrics`,
disk stats → `IOKit`, network → `getifaddrs`.
PRs welcome.

### Windows
WSL2 runs bsc as-is (Linux `/proc` available inside the VM).
Native Windows would need a full data-collection rewrite (psutil or raw WinAPI).
PRs welcome.

## license

ACSL v1.4 — Anti-Capitalist Software License
