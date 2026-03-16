package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	prevCPURaw [][]int64
	prevProcJ  map[int]int64
	prevProcT  time.Time
	prevRaplUJ int64
	prevRaplT  time.Time
)

func readCPU() ([]CoreStat, [3]float64, float64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return nil, [3]float64{}, 0
	}
	defer f.Close()

	var cur [][]int64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu") || strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}
		row := make([]int64, 7)
		for i := 0; i < 7; i++ {
			row[i], _ = strconv.ParseInt(fields[i+1], 10, 64)
		}
		cur = append(cur, row)
	}

	pcts := make([]float64, len(cur))
	if prevCPURaw != nil && len(prevCPURaw) == len(cur) {
		for i, n := range cur {
			p := prevCPURaw[i]
			var totDelta, idleDelta int64
			for j := 0; j < 7; j++ {
				totDelta += n[j] - p[j]
			}
			idleDelta = n[3] - p[3]
			if totDelta > 0 {
				pcts[i] = float64(totDelta-idleDelta) / float64(totDelta) * 100
			}
		}
	}
	prevCPURaw = cur

	// coretemp hwmon
	temps := map[int]int{}
	hwdir, _ := os.ReadDir("/sys/class/hwmon")
	for _, hw := range hwdir {
		base := "/sys/class/hwmon/" + hw.Name()
		nameb, _ := os.ReadFile(base + "/name")
		if strings.TrimSpace(string(nameb)) != "coretemp" {
			continue
		}
		entries, _ := os.ReadDir(base)
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, "_label") || !strings.HasPrefix(n, "temp") {
				continue
			}
			num := strings.TrimPrefix(strings.TrimSuffix(n, "_label"), "temp")
			lbl, _ := os.ReadFile(base + "/" + n)
			lbls := strings.TrimSpace(string(lbl))
			if !strings.HasPrefix(lbls, "Core ") {
				continue
			}
			coreN, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(lbls, "Core ")))
			if err != nil {
				continue
			}
			tinput, _ := os.ReadFile(base + "/temp" + num + "_input")
			t, _ := strconv.Atoi(strings.TrimSpace(string(tinput)))
			temps[coreN] = t / 1000
		}
	}

	freqs := map[int]int{}
	baseFreqs := map[int]int{}
	throttles := map[int]int{}
	cpuDir, _ := os.ReadDir("/sys/devices/system/cpu")
	for _, e := range cpuDir {
		name := e.Name()
		if !strings.HasPrefix(name, "cpu") {
			continue
		}
		n, err := strconv.Atoi(name[3:])
		if err != nil {
			continue
		}
		base := "/sys/devices/system/cpu/" + name
		if v, err := os.ReadFile(base + "/cpufreq/scaling_cur_freq"); err == nil {
			f, _ := strconv.Atoi(strings.TrimSpace(string(v)))
			freqs[n] = f / 1000
		}
		if v, err := os.ReadFile(base + "/cpufreq/base_frequency"); err == nil {
			f, _ := strconv.Atoi(strings.TrimSpace(string(v)))
			baseFreqs[n] = f / 1000
		}
		if v, err := os.ReadFile(base + "/thermal_throttle/core_throttle_count"); err == nil {
			f, _ := strconv.Atoi(strings.TrimSpace(string(v)))
			throttles[n] = f
		}
	}

	cores := make([]CoreStat, len(pcts))
	for i, p := range pcts {
		t := temps[i]
		if t == 0 {
			t = temps[i/2]
		}
		curF := freqs[i]
		baseF := baseFreqs[i]
		cores[i] = CoreStat{
			Pct:      p,
			FreqMHz:  curF,
			TempC:    t,
			Turbo:    curF > 0 && baseF > 0 && curF > baseF,
			Throttle: throttles[i],
		}
	}

	var load [3]float64
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			load[0], _ = strconv.ParseFloat(fields[0], 64)
			load[1], _ = strconv.ParseFloat(fields[1], 64)
			load[2], _ = strconv.ParseFloat(fields[2], 64)
		}
	}

	// RAPL power — ujoules delta / dt / 1e6 = watts
	var raplW float64
	if data, err := os.ReadFile("/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj"); err == nil {
		uj, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		now := time.Now()
		if !prevRaplT.IsZero() {
			dt := now.Sub(prevRaplT).Seconds()
			if dt > 0 {
				raplW = float64(uj-prevRaplUJ) / dt / 1e6
			}
		}
		prevRaplUJ = uj
		prevRaplT = now
	}

	return cores, load, raplW
}

func readMem() MemStat {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return MemStat{}
	}
	defer f.Close()

	mi := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		key := line[:colon]
		val := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line[colon+1:]), "kB"))
		mi[key], _ = strconv.Atoi(val)
	}

	var zt, zu int
	if data, err := os.ReadFile("/sys/block/zram0/disksize"); err == nil {
		v, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		zt = int(v >> 10)
	}
	if data, err := os.ReadFile("/sys/block/zram0/mm_stat"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 2 {
			v, _ := strconv.ParseInt(fields[1], 10, 64)
			zu = int(v >> 10)
		}
	}

	total := mi["MemTotal"]
	avail := mi["MemAvailable"]
	return MemStat{
		TotalKB:    total,
		UsedKB:     total - avail,
		SwapTotKB:  mi["SwapTotal"],
		SwapUsedKB: mi["SwapTotal"] - mi["SwapFree"],
		ZramTotKB:  zt,
		ZramUsedKB: zu,
	}
}

func readProcs() ([]ProcStat, map[string]int) {
	now := time.Now()
	var dt float64
	if !prevProcT.IsZero() {
		dt = now.Sub(prevProcT).Seconds()
	}
	prevProcT = now

	if prevProcJ == nil {
		prevProcJ = make(map[int]int64)
	}

	entries, _ := os.ReadDir("/proc")
	var procs []ProcStat
	newJ := make(map[int]int64, len(prevProcJ))
	counts := map[string]int{}
	pageKB := os.Getpagesize() / 1024

	for _, e := range entries {
		name := e.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		pid, err := strconv.Atoi(name)
		if err != nil {
			continue
		}

		statData, err := os.ReadFile("/proc/" + name + "/stat")
		if err != nil {
			continue
		}

		line := string(statData)
		i := strings.IndexByte(line, '(')
		j := strings.LastIndexByte(line, ')')
		if i < 0 || j <= i {
			continue
		}

		comm := line[i+1 : j]
		rest := strings.Fields(line[j+2:])
		if len(rest) < 22 {
			continue
		}

		state := rest[0]
		counts[state]++

		utime, _ := strconv.ParseInt(rest[11], 10, 64)
		stime, _ := strconv.ParseInt(rest[12], 10, 64)
		rssPages, _ := strconv.ParseInt(rest[21], 10, 64)
		jTotal := utime + stime

		newJ[pid] = jTotal

		var cpuPct float64
		if dt > 0 {
			if prevJ, ok := prevProcJ[pid]; ok {
				cpuPct = float64(jTotal-prevJ) / (dt * HZ) * 100
			}
		}

		var cmd string
		if cmdData, err := os.ReadFile("/proc/" + name + "/cmdline"); err == nil {
			cmd = strings.ReplaceAll(string(cmdData), "\x00", " ")
			cmd = strings.TrimSpace(cmd)
		}
		if cmd == "" {
			cmd = "[" + comm + "]"
		}

		// uid from status — only read Uid line
		var uid int
		if statusData, err := os.ReadFile("/proc/" + name + "/status"); err == nil {
			for _, l := range strings.SplitN(string(statusData), "\n", 50) {
				if strings.HasPrefix(l, "Uid:") {
					fields := strings.Fields(l)
					if len(fields) >= 2 {
						uid, _ = strconv.Atoi(fields[1])
					}
					break
				}
			}
		}

		procs = append(procs, ProcStat{
			PID:   pid,
			Comm:  comm,
			Cmd:   cmd,
			UID:   uid,
			CPU:   cpuPct,
			MemKB: int(rssPages) * pageKB,
			State: state,
		})
	}

	prevProcJ = newJ
	return procs, counts
}
