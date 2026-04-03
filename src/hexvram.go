package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// findNvidiaPCIAddr — scan /sys/bus/pci/devices for NVIDIA vendor (0x10de)
// returns path like "/sys/bus/pci/devices/0000:01:00.0"
func findNvidiaPCIAddr() string {
	devs, err := os.ReadDir("/sys/bus/pci/devices")
	if err != nil {
		return ""
	}
	for _, d := range devs {
		base := "/sys/bus/pci/devices/" + d.Name()
		vb, err := os.ReadFile(base + "/vendor")
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(vb)) == "0x10de" {
			// verify it's a display class (0x03xx)
			cb, _ := os.ReadFile(base + "/class")
			cls := strings.TrimSpace(string(cb))
			if strings.HasPrefix(cls, "0x03") {
				return base
			}
		}
	}
	return ""
}

// vramBarSize — read BAR1 size from /sys/bus/pci/devices/ADDR/resource
// resource file: each line = "start end flags", BAR1 = line index 1
func vramBarSize(pciBase string) int64 {
	raw, err := os.ReadFile(pciBase + "/resource")
	if err != nil {
		return 0
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	// BAR1 = index 1 (0-indexed)
	if len(lines) < 2 {
		return 0
	}
	var start, end, flags int64
	fmt.Sscanf(lines[1], "0x%x 0x%x 0x%x", &start, &end, &flags)
	if end <= start || start == 0 {
		return 0
	}
	return end - start + 1
}

// vramMapData holds the mmap'd VRAM BAR slice + file descriptor
type vramMapData struct {
	data   []byte   // mmap'd data; nil if using file mode
	file   *os.File // file handle for per-read fallback; nil if mmap ok
	size   int64
	pciDev string
	err    string
}

var vramCache vramMapData
var vramCacheInit bool

// openVRAMBar — mmap NVIDIA BAR1 (framebuffer aperture) read-only
// BAR1 gives a CPU-visible window into VRAM. Returns mapped slice or error string.
// Note: requires read permission on /sys/bus/pci/devices/ADDR/resource1
// On most systems this needs root or at least group 'video'.
func openVRAMBar() vramMapData {
	if vramCacheInit {
		return vramCache
	}
	vramCacheInit = true

	pci := findNvidiaPCIAddr()
	if pci == "" {
		vramCache = vramMapData{err: "no NVIDIA GPU found in /sys/bus/pci/devices"}
		return vramCache
	}

	barSize := vramBarSize(pci)
	if barSize == 0 {
		vramCache = vramMapData{pciDev: pci, err: "BAR1 size=0 (driver may be using it exclusively)"}
		return vramCache
	}

	// cap at 256MB for the initial mmap — full 4GB would be slow to map
	mapSize := barSize
	if mapSize > 256<<20 {
		mapSize = 256 << 20
	}

	f, err := os.OpenFile(pci+"/resource1", os.O_RDONLY, 0)
	if err != nil {
		vramCache = vramMapData{pciDev: pci, err: "resource1: " + err.Error()}
		return vramCache
	}
	data, err2 := syscall.Mmap(int(f.Fd()), 0, int(mapSize),
		syscall.PROT_READ, syscall.MAP_SHARED)
	if err2 != nil {
		// mmap failed (common on some NVIDIA configs) — fall back to file reads
		vramCache = vramMapData{
			file:   f,
			size:   barSize,
			pciDev: pci,
		}
		return vramCache
	}
	f.Close()

	vramCache = vramMapData{
		data:   data,
		size:   barSize,
		pciDev: pci,
	}
	return vramCache
}

// readVRAMProcs — per-process VRAM from nvidia-smi --query-compute-apps
// returns lines like "pid name usedMB"
func readVRAMProcs() []string {
	out := runCmd(2e9, "nvidia-smi",
		"--query-compute-apps=pid,process_name,used_gpu_memory",
		"--format=csv,noheader,nounits")
	if out == "" {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func drawHexVRAM(buf *strings.Builder, rows, cols, paneW, sepX, dumpX, dumpW, bpr, paneH int,
	ss *SysState, ui *UI, t *Theme, search []byte) {
	defer func() {
		if r := recover(); r != nil {
			buf.WriteString(pos(3, dumpX))
			buf.WriteString(ansiCol(t.WARN) + fmt.Sprintf("vram panic: %v", r) + RESET + CLEOL)
		}
	}()

	vm := openVRAMBar()
	dim := DIM + ansiCol(t.USB)
	warn := ansiCol(t.WARN)

	// ── left pane: VRAM info + per-process allocations ────────────────────────
	row := 1
	writePane := func(r int, s string) {
		buf.WriteString(pos(r, 0))
		runes := []rune(s)
		if len(runes) > paneW-1 {
			s = string(runes[:paneW-1])
		}
		buf.WriteString(s + RESET + CLEOL)
	}

	// GPU header
	ss.mu.RLock()
	gpu := ss.GPU
	ss.mu.RUnlock()
	if gpu.Model != "" {
		vu := int(gpu.VRAMUsed >> 20)
		vt := int(gpu.VRAMTot >> 20)
		writePane(row, ansiCol(t.GPU)+gpu.Model+RESET)
		row++
		writePane(row, fmt.Sprintf(dim+" VRAM %s/%s %d%%%s",
			fmtMem(vu*1024), fmtMem(vt*1024), pct2(vu, vt), RESET))
		row++
		writePane(row, fmt.Sprintf(dim+" BAR1  %s%s", fmtBufSize(int(vm.size)), RESET))
		row++
	}
	row++

	// per-process VRAM
	if row < paneH+1 {
		writePane(row, ansiCol(t.USB)+BOLD+" procs"+RESET)
		row++
		procs := readVRAMProcs()
		if len(procs) == 0 {
			writePane(row, dim+"  (no compute apps)"+RESET)
			row++
		} else {
			for _, p := range procs {
				if row >= paneH+1 {
					break
				}
				fields := strings.SplitN(p, ", ", 3)
				if len(fields) == 3 {
					pid, name, mem := fields[0], fields[1], fields[2]
					// shorten name to basename
					if i := strings.LastIndexByte(name, '/'); i >= 0 {
						name = name[i+1:]
					}
					writePane(row, fmt.Sprintf("%s%5s %s%-12s %s%sMB%s",
						dim, pid, RESET, name, ansiCol(t.RAM), mem, RESET))
				} else {
					writePane(row, dim+"  "+p+RESET)
				}
				row++
			}
		}
	}

	// status / error
	row++
	if vm.err != "" {
		// clear entire left pane
		for r := 1; r < paneH+1; r++ {
			buf.WriteString(pos(r, 0) + CLEOL)
		}
		// clear entire dump pane, then show error
		r := 1
		for ; r < rows-1; r++ {
			buf.WriteString(pos(r, dumpX) + CLEOL)
		}
		r = 2
		wl := func(s string) {
			buf.WriteString(pos(r, dumpX) + s + RESET)
			r++
		}
		wl(warn + "VRAM BAR1 unavailable")
		wl(dim + vm.err)
		if vm.pciDev != "" {
			wl(dim + "pci: " + vm.pciDev)
			wl(dim + "sudo chmod o+r " + vm.pciDev + "/resource1")
		}
		return
	}

	// clear rest of left pane
	for ; row < paneH+1; row++ {
		buf.WriteString(pos(row, 0) + CLEOL)
	}

	// ── right pane: hex dump of BAR1 ─────────────────────────────────────────
	// clear top rows that may have stale content from previous hex source
	buf.WriteString(pos(1, dumpX) + CLEOL)

	totalBytes := vm.size
	if vm.data != nil {
		totalBytes = int64(len(vm.data))
	}
	scroll := int64(ui.HexScroll) * int64(bpr)
	if scroll > totalBytes {
		scroll = totalBytes
	}

	for r := 0; r < paneH; r++ {
		off := scroll + int64(r*bpr)
		if off >= totalBytes {
			buf.WriteString(pos(r+1, dumpX) + CLEOL)
			continue
		}
		end := off + int64(bpr)
		if end > totalBytes {
			end = totalBytes
		}
		chunk := make([]byte, bpr)
		if vm.data != nil {
			// mmap path — safe copy with bus error recovery
			func() {
				defer func() { recover() }()
				copy(chunk, vm.data[off:end])
			}()
		} else if vm.file != nil {
			// file read path
			vm.file.ReadAt(chunk, off)
		}

		allZero := true
		for _, b := range chunk[:end-off] {
			if b != 0 {
				allZero = false
				break
			}
		}
		lineCol := ansiCol(t.GPU)
		if allZero {
			lineCol = dim
		}
		line := hexLine(off, 0, chunk[:end-off], bpr, search, lineCol, t)
		buf.WriteString(pos(r+1, dumpX))
		buf.WriteString(lineCol + line + RESET + CLEOL)
	}
}
