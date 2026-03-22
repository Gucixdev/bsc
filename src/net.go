package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// readNet — /proc/net/dev delta + ioctl IP + wifi + IPv6 + MAC
var (
	prevNetRaw map[string][2]int64
	prevNetT   time.Time
)

func readNet() ([]NetIface, string) {
	now := time.Now()
	dt := 1.0
	if !prevNetT.IsZero() {
		dt = now.Sub(prevNetT).Seconds()
	}
	prevNetT = now

	cur := map[string][2]int64{}
	f, _ := os.Open("/proc/net/dev")
	if f != nil {
		sc := bufio.NewScanner(f)
		sc.Scan() // header 1
		sc.Scan() // header 2
		for sc.Scan() {
			line := sc.Text()
			colon := strings.IndexByte(line, ':')
			if colon < 0 {
				continue
			}
			name := strings.TrimSpace(line[:colon])
			fields := strings.Fields(line[colon+1:])
			if len(fields) < 9 {
				continue
			}
			rx, _ := strconv.ParseInt(fields[0], 10, 64)
			tx, _ := strconv.ParseInt(fields[8], 10, 64)
			cur[name] = [2]int64{rx, tx}
		}
		f.Close()
	}

	// open socket for ioctl
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		fd = -1
	}
	defer func() {
		if fd >= 0 {
			syscall.Close(fd)
		}
	}()

	var result []NetIface
	entries, _ := os.ReadDir("/sys/class/net")
	for _, e := range entries {
		name := e.Name()
		if name == "lo" {
			continue
		}

		iface := NetIface{Name: name}

		// rx/tx bps
		if c, ok := cur[name]; ok && prevNetRaw != nil {
			p := prevNetRaw[name]
			if dt > 0 {
				iface.RxBps = float64(c[0]-p[0]) / dt
				iface.TxBps = float64(c[1]-p[1]) / dt
			}
		}

		// IP via ioctl SIOCGIFADDR
		if fd >= 0 {
			var ifreq [40]byte
			copy(ifreq[:16], name)
			if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
				uintptr(fd), 0x8915, uintptr(unsafe.Pointer(&ifreq[0]))); errno == 0 {
				iface.IP = fmt.Sprintf("%d.%d.%d.%d",
					ifreq[20], ifreq[21], ifreq[22], ifreq[23])
			}
			// netmask → prefix
			var ifmask [40]byte
			copy(ifmask[:16], name)
			if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
				uintptr(fd), 0x891b, uintptr(unsafe.Pointer(&ifmask[0]))); errno == 0 {
				bits := 0
				for i := 20; i < 24; i++ {
					b := ifmask[i]
					for b != 0 {
						bits += int(b & 1)
						b >>= 1
					}
				}
				iface.Prefix = bits
			}
		}

		// MAC
		if v, err := os.ReadFile("/sys/class/net/" + name + "/address"); err == nil {
			iface.MAC = strings.TrimSpace(string(v))
		}
		// speed
		if v, err := os.ReadFile("/sys/class/net/" + name + "/speed"); err == nil {
			iface.SpeedMb, _ = strconv.Atoi(strings.TrimSpace(string(v)))
		}
		// up
		if v, err := os.ReadFile("/sys/class/net/" + name + "/operstate"); err == nil {
			iface.Up = strings.TrimSpace(string(v)) == "up"
		}

		// IPv6
		if v, err := os.ReadFile("/proc/net/if_inet6"); err == nil {
			for _, line := range strings.Split(string(v), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 6 && fields[5] == name {
					addr := fields[0]
					var parts []string
					for i := 0; i < len(addr); i += 4 {
						parts = append(parts, addr[i:i+4])
					}
					iface.IPv6 = strings.Join(parts, ":")
					break
				}
			}
		}

		// WiFi SSID
		ssid := runCmd(time.Second, "iwgetid", "-r", name)
		if ssid == "" {
			out := runCmd(time.Second, "iw", "dev", name, "link")
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "SSID:") {
					ssid = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "SSID:"))
				}
			}
		}
		iface.SSID = ssid

		// signal from /proc/net/wireless
		if v, err := os.ReadFile("/proc/net/wireless"); err == nil {
			for _, line := range strings.Split(string(v), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), name+":") {
					fields := strings.Fields(line)
					if len(fields) >= 4 {
						s := strings.TrimSuffix(fields[3], ".")
						iface.Signal, _ = strconv.Atoi(s)
					}
				}
			}
		}

		result = append(result, iface)
	}

	prevNetRaw = cur

	// gateway
	gw := ""
	if v, err := os.ReadFile("/proc/net/route"); err == nil {
		for _, line := range strings.Split(string(v), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[1] == "00000000" {
				g, _ := strconv.ParseUint(fields[2], 16, 32)
				b := [4]byte{byte(g), byte(g >> 8), byte(g >> 16), byte(g >> 24)}
				gw = fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
				break
			}
		}
	}
	return result, gw
}

// netCapRunning — per-iface capture goroutine guard, protected by NetCapMu
var netCapRunning = map[string]bool{}

// startNetCapture — noop; actual capture started on demand by ensureNetCap
func startNetCapture(ss *SysState) {}

// ensureNetCap — starts one goroutine per interface on first call for that iface.
// Accumulates raw packets into HexNetBufs[iface], capped at 128KB.
func ensureNetCap(ss *SysState, iface string) {
	ss.NetCapMu.Lock()
	already := netCapRunning[iface]
	if !already {
		netCapRunning[iface] = true
	}
	ss.NetCapMu.Unlock()
	if already {
		return
	}
	go func() {
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
		if err != nil {
			ss.NetCapMu.Lock()
			netCapRunning[iface] = false // allow retry
			ss.NetCapMu.Unlock()
			return
		}
		defer syscall.Close(fd)
		// read ifindex from sysfs
		idx := 0
		if v, err2 := os.ReadFile("/sys/class/net/" + iface + "/ifindex"); err2 == nil {
			idx, _ = strconv.Atoi(strings.TrimSpace(string(v)))
		}
		_ = idx // bind is best-effort
		buf := make([]byte, 65536)
		const cap128k = 128 * 1024
		for {
			n, _, err := syscall.Recvfrom(fd, buf, 0)
			if err != nil || n == 0 {
				continue
			}
			ss.NetCapMu.Lock()
			if ss.HexNetBufs == nil {
				ss.HexNetBufs = map[string][]byte{}
			}
			prev := ss.HexNetBufs[iface]
			prev = append(prev, buf[:n]...)
			if len(prev) > cap128k {
				prev = prev[len(prev)-cap128k:]
			}
			ss.HexNetBufs[iface] = prev
			ss.NetCapMu.Unlock()
		}
	}()
}

func htons(v uint16) uint16 { return (v >> 8) | (v << 8) }
