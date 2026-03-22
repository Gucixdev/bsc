# pipboy

TUI system monitor. Go, no deps, static binary.

```
bash scripts/bsc-cmd build go
bash scripts/bsc-cmd install go -y
pipboy
```

---

**OVW** — CPU per-core (freq/temp/turbo/throttle/RAPL) · RAM/swap/zram · GPU (nvidia/amd/intel) · disk (MB/s, IOPS, latency, SMART) · net (rx/tx, IP, wifi SSID/signal) · VMs/containers · audio servers · hooks · process list

**DEV** — kernel cmdline · sysctl · IRQs · CPU flags · syscall trace (eBPF/perf/proc) · registers + disasm

**SEC** — kernel hardening · taint · rootkit indicators · firewall/AppArmor/SELinux/firejail · network vulns · listening ports · connections · users

**HEX** — process memory · raw block device · packet capture (AF_PACKET)

---

`a` = anonymous mode (hides IPs/MACs/users for screenshots)
