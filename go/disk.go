package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// readDisks — /proc/diskstats delta + mounts + SMART
// diskRaw fields: [0]=rd_sectors [1]=wr_sectors [2]=io_ticks [3]=rd_ios [4]=wr_ios [5]=rd_ticks [6]=wr_ticks
var (
	prevDiskRaw map[string][7]int64
	prevDiskT   time.Time
	smartCache  map[string]int
	smartCacheT map[string]time.Time
)

func readDisks() []DiskStat {
	now := time.Now()
	dt := 1.0
	if !prevDiskT.IsZero() {
		dt = now.Sub(prevDiskT).Seconds()
	}
	prevDiskT = now
	if smartCache == nil {
		smartCache = map[string]int{}
		smartCacheT = map[string]time.Time{}
	}

	cur := map[string][7]int64{}
	rdIOPS := map[string]float64{}
	wrIOPS := map[string]float64{}
	rdLatMs := map[string]float64{}
	wrLatMs := map[string]float64{}
	rdTotal := map[string]int64{}
	wrTotal := map[string]int64{}
	f, _ := os.Open("/proc/diskstats")
	if f != nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 14 {
				continue
			}
			dev := fields[2]
			rdSect, _ := strconv.ParseInt(fields[5], 10, 64)
			wrSect, _ := strconv.ParseInt(fields[9], 10, 64)
			ioTicks, _ := strconv.ParseInt(fields[12], 10, 64)
			rdIos, _ := strconv.ParseInt(fields[3], 10, 64)
			wrIos, _ := strconv.ParseInt(fields[7], 10, 64)
			rdTicks, _ := strconv.ParseInt(fields[6], 10, 64)
			wrTicks, _ := strconv.ParseInt(fields[10], 10, 64)
			cur[dev] = [7]int64{rdSect, wrSect, ioTicks, rdIos, wrIos, rdTicks, wrTicks}
			rdTotal[dev] = rdSect * 512
			wrTotal[dev] = wrSect * 512
			if prevDiskRaw != nil {
				p := prevDiskRaw[dev]
				dRdIos := float64(rdIos - p[3])
				dWrIos := float64(wrIos - p[4])
				if dt > 0 {
					rdIOPS[dev] = dRdIos / dt
					wrIOPS[dev] = dWrIos / dt
				}
				if dRdIos > 0 {
					rdLatMs[dev] = float64(rdTicks-p[5]) / dRdIos
				}
				if dWrIos > 0 {
					wrLatMs[dev] = float64(wrTicks-p[6]) / dWrIos
				}
			}
		}
		f.Close()
	}

	// mounts → partitions
	partMap := map[string][]PartStat{}
	skipFS := map[string]bool{
		"proc": true, "sysfs": true, "tmpfs": true, "devtmpfs": true,
		"devpts": true, "cgroup": true, "cgroup2": true, "pstore": true,
		"securityfs": true, "debugfs": true, "hugetlbfs": true, "mqueue": true,
		"fusectl": true, "bpf": true, "tracefs": true, "configfs": true,
		"ramfs": true, "efivarfs": true,
	}
	mf, _ := os.Open("/proc/mounts")
	if mf != nil {
		sc := bufio.NewScanner(mf)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 3 {
				continue
			}
			src, mount, fs := fields[0], fields[1], fields[2]
			if skipFS[fs] {
				continue
			}
			// strip partition number to get parent dev
			dev := strings.TrimPrefix(src, "/dev/")
			parent := dev
			for len(parent) > 0 && parent[len(parent)-1] >= '0' && parent[len(parent)-1] <= '9' {
				parent = parent[:len(parent)-1]
			}
			var st syscall.Statfs_t
			if err := syscall.Statfs(mount, &st); err == nil {
				tot := int64(st.Blocks) * int64(st.Bsize)
				avail := int64(st.Bavail) * int64(st.Bsize)
				partMap[parent] = append(partMap[parent], PartStat{
					Dev: dev, Mount: mount, FS: fs,
					Used: tot - avail, Total: tot,
				})
			}
		}
		mf.Close()
	}

	// build DiskStat list for real block devs
	var result []DiskStat
	entries, _ := os.ReadDir("/sys/block")
	for _, e := range entries {
		dev := e.Name()
		base := "/sys/block/" + dev

		// skip loop, ram, zram
		if strings.HasPrefix(dev, "loop") || strings.HasPrefix(dev, "ram") || strings.HasPrefix(dev, "zram") {
			continue
		}

		d := DiskStat{Dev: dev}

		// model + size
		if v, err := os.ReadFile(base + "/device/model"); err == nil {
			d.Model = strings.TrimSpace(string(v))
		}
		if v, err := os.ReadFile(base + "/size"); err == nil {
			sectors, _ := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64)
			d.SizeBytes = sectors * 512
		}
		// rotary
		if v, err := os.ReadFile(base + "/queue/rotational"); err == nil {
			d.Rotary = strings.TrimSpace(string(v)) == "1"
		}
		// removable
		if v, err := os.ReadFile(base + "/removable"); err == nil {
			d.Removable = strings.TrimSpace(string(v)) == "1"
		}
		// scheduler
		if v, err := os.ReadFile(base + "/queue/scheduler"); err == nil {
			s := string(v)
			i := strings.Index(s, "[")
			j := strings.Index(s, "]")
			if i >= 0 && j > i {
				d.Sched = s[i+1 : j]
			}
		}

		// iostats delta
		if c, ok := cur[dev]; ok {
			if prevDiskRaw != nil {
				p := prevDiskRaw[dev]
				if dt > 0 {
					d.ReadBps = float64(c[0]-p[0]) * 512 / dt
					d.WriteBps = float64(c[1]-p[1]) * 512 / dt
					d.Busy = float64(c[2]-p[2]) / (dt * 1000) * 100
				}
			}
		}
		d.RdIOPS = rdIOPS[dev]
		d.WrIOPS = wrIOPS[dev]
		d.RdLatMs = rdLatMs[dev]
		d.WrLatMs = wrLatMs[dev]
		d.RdTotal = rdTotal[dev]
		d.WrTotal = wrTotal[dev]

		// temperature: hwmon sysfs first (no deps), smartctl fallback
		if t, ok := smartCacheT[dev]; !ok || time.Since(t) > SMART_TTL {
			temp := 0
			// NVMe/SATA: /sys/block/devX/device/hwmon*/temp1_input
			if hwDir, err := os.ReadDir(base + "/device"); err == nil {
				for _, h := range hwDir {
					if !strings.HasPrefix(h.Name(), "hwmon") {
						continue
					}
					if v, err := os.ReadFile(base + "/device/" + h.Name() + "/temp1_input"); err == nil {
						t, _ := strconv.Atoi(strings.TrimSpace(string(v)))
						if t > 0 {
							temp = t / 1000
						}
					}
				}
			}
			// NVMe: /sys/class/nvme/nvme0/hwmon*/temp1_input
			if temp == 0 {
				nvme := strings.TrimSuffix(dev, "n1") // nvme0n1 → nvme0
				if nvmeDir, err := os.ReadDir("/sys/class/nvme/" + nvme); err == nil {
					for _, h := range nvmeDir {
						if !strings.HasPrefix(h.Name(), "hwmon") {
							continue
						}
						p := "/sys/class/nvme/" + nvme + "/" + h.Name() + "/temp1_input"
						if v, err := os.ReadFile(p); err == nil {
							t, _ := strconv.Atoi(strings.TrimSpace(string(v)))
							if t > 0 {
								temp = t / 1000
							}
						}
					}
				}
			}
			// smartctl fallback (requires root or sg group)
			if temp == 0 {
				out := runCmd(3*time.Second, "smartctl", "-A", "/dev/"+dev)
				for _, line := range strings.Split(out, "\n") {
					if strings.Contains(line, "Temperature") {
						fields := strings.Fields(line)
						if len(fields) >= 10 {
							temp, _ = strconv.Atoi(fields[9])
						}
					}
				}
			}
			smartCache[dev] = temp
			smartCacheT[dev] = time.Now()
		}
		d.TempC = smartCache[dev]

		d.Parts = partMap[dev]
		result = append(result, d)
	}

	prevDiskRaw = cur
	return result
}
