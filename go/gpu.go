package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	prevGPU  GPUStat
	prevGPUT time.Time
)

func readGPU() GPUStat {
	if !prevGPUT.IsZero() && time.Since(prevGPUT) < GPU_TTL {
		return prevGPU
	}
	prevGPUT = time.Now()

	g := gpuNvidiaSMI()
	if g.Source == "" {
		g = gpuNvidiaProc()
	}
	if g.Source == "" {
		g = gpuHwmon()
	}
	if g.Source == "" {
		g = gpuRocm()
	}

	prevGPU = g
	return g
}

// nvidia-smi — primary for NVIDIA; gets driver/fan/power
func gpuNvidiaSMI() GPUStat {
	out := runCmd(2*time.Second, "nvidia-smi",
		"--query-gpu=name,utilization.gpu,temperature.gpu,memory.used,memory.total,power.draw,driver_version,fan.speed",
		"--format=csv,noheader,nounits")
	if out == "" {
		return GPUStat{}
	}
	fields := strings.Split(out, ",")
	if len(fields) < 6 {
		return GPUStat{}
	}
	trim := func(i int) string {
		if i >= len(fields) {
			return ""
		}
		return strings.TrimSpace(fields[i])
	}
	g := GPUStat{Source: "nvidia-smi", Fan: -1}
	g.Model = strings.NewReplacer("NVIDIA GeForce ", "", "NVIDIA ", "").Replace(trim(0))
	g.Util, _ = strconv.Atoi(trim(1))
	g.TempC, _ = strconv.Atoi(trim(2))
	vu, _ := strconv.ParseInt(trim(3), 10, 64)
	vt, _ := strconv.ParseInt(trim(4), 10, 64)
	g.VRAMUsed = vu << 20
	g.VRAMTot = vt << 20
	g.Power, _ = strconv.ParseFloat(trim(5), 64)
	g.Driver = trim(6)
	if fan, err := strconv.Atoi(trim(7)); err == nil {
		g.Fan = fan
	}
	return g
}

// /proc/driver/nvidia — fallback when nvidia-smi not in PATH but module loaded
func gpuNvidiaProc() GPUStat {
	gpus, err := os.ReadDir("/proc/driver/nvidia/gpus")
	if err != nil || len(gpus) == 0 {
		return GPUStat{}
	}
	g := GPUStat{Source: "nvidia-proc", Fan: -1}
	info, _ := os.ReadFile("/proc/driver/nvidia/gpus/" + gpus[0].Name() + "/information")
	for _, line := range strings.Split(string(info), "\n") {
		if strings.HasPrefix(line, "Model:") {
			g.Model = strings.TrimSpace(strings.TrimPrefix(line, "Model:"))
			g.Model = strings.NewReplacer("NVIDIA GeForce ", "", "NVIDIA ", "").Replace(g.Model)
		}
		// "Video Memory:   4096 MB"
		if strings.HasPrefix(line, "Video Memory:") {
			f := strings.Fields(strings.TrimPrefix(line, "Video Memory:"))
			if len(f) >= 1 {
				n, _ := strconv.ParseInt(f[0], 10, 64)
				g.VRAMTot = n << 20 // MB → bytes
			}
		}
	}
	// VRAM used: not in /proc/driver/nvidia — run nvidia-smi for used only
	if g.VRAMTot > 0 {
		out := runCmd(2*time.Second, "nvidia-smi",
			"--query-gpu=memory.used", "--format=csv,noheader,nounits")
		if out != "" {
			n, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
			if err == nil {
				g.VRAMUsed = n << 20
			}
		}
	}
	if v, err := os.ReadFile("/sys/module/nvidia/version"); err == nil {
		g.Driver = strings.TrimSpace(string(v))
	}
	// temp via hwmon with name "nvidia"
	hwdir, _ := os.ReadDir("/sys/class/hwmon")
	for _, hw := range hwdir {
		base := "/sys/class/hwmon/" + hw.Name()
		nameb, _ := os.ReadFile(base + "/name")
		if strings.TrimSpace(string(nameb)) != "nvidia" {
			continue
		}
		if v, err := os.ReadFile(base + "/temp1_input"); err == nil {
			t, _ := strconv.Atoi(strings.TrimSpace(string(v)))
			g.TempC = t / 1000
		}
	}
	if g.Model == "" {
		return GPUStat{}
	}
	return g
}

// gpuModelFromDRM — find product_name for PCI GPU with given vendor ID (e.g. "0x1002")
func gpuModelFromDRM(vendorID string) string {
	cards, _ := os.ReadDir("/sys/class/drm")
	for _, c := range cards {
		if !strings.HasPrefix(c.Name(), "card") || strings.Contains(c.Name(), "-") {
			continue
		}
		base := "/sys/class/drm/" + c.Name() + "/device"
		vb, _ := os.ReadFile(base + "/vendor")
		if strings.TrimSpace(string(vb)) != vendorID {
			continue
		}
		if b, _ := os.ReadFile(base + "/product_name"); len(b) > 0 {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// hwmon — AMD (amdgpu), Intel (i915/xe), Nouveau
// AMD/Intel: model from DRM product_name, VRAM from mem_info_vram_*, util from gpu_busy_percent
func gpuHwmon() GPUStat {
	hwdir, _ := os.ReadDir("/sys/class/hwmon")
	for _, hw := range hwdir {
		base := "/sys/class/hwmon/" + hw.Name()
		nameb, _ := os.ReadFile(base + "/name")
		hwname := strings.TrimSpace(string(nameb))

		var vendorID, fallbackModel string
		switch hwname {
		case "amdgpu":
			vendorID, fallbackModel = "0x1002", "AMD GPU"
		case "nouveau":
			vendorID, fallbackModel = "0x10de", "NVIDIA GPU"
		case "i915":
			vendorID, fallbackModel = "0x8086", "Intel GPU"
		case "xe":
			vendorID, fallbackModel = "0x8086", "Intel Xe GPU"
		default:
			continue
		}

		model := gpuModelFromDRM(vendorID)
		if model == "" {
			model = fallbackModel
		}
		g := GPUStat{Source: hwname, Model: model, Fan: -1}

		if v, err := os.ReadFile(base + "/temp1_input"); err == nil {
			t, _ := strconv.Atoi(strings.TrimSpace(string(v)))
			g.TempC = t / 1000
		}
		if v, err := os.ReadFile(base + "/power1_average"); err == nil {
			p, _ := strconv.ParseFloat(strings.TrimSpace(string(v)), 64)
			g.Power = p / 1e6
		}

		// fan — AMD and some Intel
		if rpm, err := os.ReadFile(base + "/fan1_input"); err == nil {
			r, _ := strconv.Atoi(strings.TrimSpace(string(rpm)))
			if maxb, err2 := os.ReadFile(base + "/fan1_max"); err2 == nil {
				m, _ := strconv.Atoi(strings.TrimSpace(string(maxb)))
				if m > 0 {
					g.Fan = 100 * r / m
				}
			}
		}

		// AMD: VRAM via device symlink
		if hwname == "amdgpu" {
			real, _ := filepath.EvalSymlinks(base)
			dev := filepath.Dir(real)
			if v, err := os.ReadFile(dev + "/mem_info_vram_used"); err == nil {
				n, _ := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64)
				g.VRAMUsed = n
			}
			if v, err := os.ReadFile(dev + "/mem_info_vram_total"); err == nil {
				n, _ := strconv.ParseInt(strings.TrimSpace(string(v)), 10, 64)
				g.VRAMTot = n
			}
		}

		// util: gpu_busy_percent from drm (AMD, Intel i915/xe)
		drm, _ := os.ReadDir("/sys/class/drm")
		for _, card := range drm {
			if strings.Contains(card.Name(), "-") {
				continue
			}
			bp := "/sys/class/drm/" + card.Name() + "/device/gpu_busy_percent"
			if v, err := os.ReadFile(bp); err == nil {
				g.Util, _ = strconv.Atoi(strings.TrimSpace(string(v)))
				break
			}
		}

		return g
	}
	return GPUStat{}
}

// rocm-smi — AMD ROCm fallback (JSON output)
func gpuRocm() GPUStat {
	out := runCmd(3*time.Second, "rocm-smi", "-a", "--json")
	if out == "" {
		return GPUStat{}
	}
	g := GPUStat{Source: "rocm", Model: "AMD GPU", Fan: -1}
	findVal := func(key string) string {
		idx := strings.Index(out, key)
		if idx < 0 {
			return ""
		}
		rest := out[idx+len(key):]
		start := strings.IndexByte(rest, '"')
		if start < 0 {
			return ""
		}
		end := strings.IndexByte(rest[start+1:], '"')
		if end < 0 {
			return ""
		}
		return rest[start+1 : start+1+end]
	}
	if v := findVal(`"GPU use (%)":`); v != "" {
		g.Util, _ = strconv.Atoi(v)
	}
	if v := findVal(`"Temperature (Sensor edge) (C)":`); v != "" {
		t, _ := strconv.ParseFloat(v, 64)
		g.TempC = int(t)
	}
	if v := findVal(`"Average Graphics Package Power (W)":`); v != "" {
		g.Power, _ = strconv.ParseFloat(v, 64)
	}
	if v := findVal(`"VRAM Total Used Memory (B)":`); v != "" {
		n, _ := strconv.ParseInt(v, 10, 64)
		g.VRAMUsed = n
	}
	if v := findVal(`"VRAM Total Memory (B)":`); v != "" {
		n, _ := strconv.ParseInt(v, 10, 64)
		g.VRAMTot = n
	}
	if g.Util == 0 && g.TempC == 0 {
		return GPUStat{}
	}
	return g
}
