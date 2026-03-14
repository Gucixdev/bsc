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
- per-core syscall trace: eBPF or /proc fallback, run-length encoded, `←→` to switch core
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

`~/.config/bsc/theme.json` — xterm-256 color indices:

```json
{
  "HDR": 208,  "CPU": 93,  "GPU": 82,
  "RAM": 220,  "DISK": 82, "NET": 33,
  "SEL": 226,  "USB": 245, "WARN": 196
}
```

## syscall trace

Uses **eBPF** (`bpftrace`) when available — needs `CAP_BPF` or root.
Falls back to `/proc/PID/syscall` polling at 10ms per core.
Run-length encoded: `futex(...) ×8492` shows how long a process sleeps.

## optional tools

| tool | used for |
|------|---------|
| `bpftrace` | eBPF syscall trace per core |
| `ndisasm` / `objdump` | disassembly in DEV |
| `pactl` / `wpctl` / `pw-dump` | audio detail |
| `nvidia-smi` | nvidia GPU stats |
| `sensors` / hwmon | temps |

## license

MIT
