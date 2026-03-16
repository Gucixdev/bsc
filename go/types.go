package main

import (
	"sync"
	"time"
)

// ── TYPES ────────────────────────────────────────────────────────────────────

type CoreStat struct {
	Pct      float64
	FreqMHz  int
	TempC    int
	Turbo    bool
	Throttle int
}

type MemStat struct {
	TotalKB, UsedKB       int
	SwapTotKB, SwapUsedKB int
	ZramTotKB, ZramUsedKB int
}

type ProcStat struct {
	PID       int
	Comm      string
	Cmd       string
	UID       int
	CPU       float64
	SmoothCPU float64 // EMA of CPU; used for stable sort
	MemKB     int
	State     string
}

// GhostProc — a dead process kept visible for GHOST_TTL seconds
type GhostProc struct {
	ProcStat
	DiedAt time.Time
}

type GPUStat struct {
	Model    string
	Driver   string
	Fan      int // -1 = not available
	VRAMUsed int64
	VRAMTot  int64
	Util     int
	TempC    int
	Power    float64
	Source   string
}

type PartStat struct {
	Dev   string
	Mount string
	FS    string
	Used  int64
	Total int64
}

type DiskStat struct {
	Dev       string
	Model     string
	SizeBytes int64
	ReadBps   float64
	WriteBps  float64
	Busy      float64
	RdIOPS    float64
	WrIOPS    float64
	RdLatMs   float64 // avg read latency ms
	WrLatMs   float64 // avg write latency ms
	RdTotal   int64   // bytes read since boot
	WrTotal   int64   // bytes written since boot
	TempC     int
	Sched     string
	Rotary    bool
	Removable bool
	Optical   bool
	Parts     []PartStat
}

type NetIface struct {
	Name    string
	RxBps   float64
	TxBps   float64
	IP      string
	Prefix  int
	IPv6    string
	MAC     string
	SpeedMb int
	SSID    string
	Signal  int
	Up      bool
}

type AudioServer struct {
	Name   string
	Active bool
	Lines  []string
}

type VMInfo struct {
	Name     string
	Status   string // run/stop/pause/new
	RssKB    int
	RunFor   int64  // uptime in seconds
	ID       string // container ID prefix
	ExitCode int
}

type VMStat struct {
	KVMExists   bool
	KVMVendor   string // Intel | AMD | ""
	QEMUVMs     []VMInfo
	VBoxVMs     []VMInfo
	VMwareVMs   []VMInfo
	DockerVMs   []VMInfo
	PodmanVMs   []VMInfo
	BwrapCount  int
	QEMUInst    bool
	VBoxInst    bool
	VMwareInst  bool
	DockerInst  bool
	PodmanInst  bool
	BwrapInst   bool
	Firewall    string
	AppArmor    bool
	SELinux     bool
}

type BattInfo struct {
	Pct      int
	Charging bool
	Full     bool
	Watts    float64
}

type IRQDelta struct {
	Name  string
	Count int64
	Delta int64
}

type TraceEntry struct {
	Syscall string
	Count   int
}

const histLen = 30

// SysState — collected data; mu protects all fields
type SysState struct {
	mu          sync.RWMutex
	Ghosts      map[int]GhostProc // pid → ghost; decays after GHOST_TTL
	Cores       []CoreStat
	Load        [3]float64
	RaplW       float64
	Mem         MemStat
	Procs       []ProcStat
	ProcCnts    map[string]int
	GPU         GPUStat
	Disks       []DiskStat
	Removable   []DiskStat
	Nets        []NetIface
	Gateway     string
	Audio       []AudioServer
	USB         []string
	VMs         VMStat
	Hooks       []string
	Battery     BattInfo
	Uptime      int64
	IRQs        []IRQDelta
	// history ring buffers — appended every collect tick, trimmed to histLen
	HistCPU   []float64
	HistGPU   []float64
	HistVRAM  []float64            // VRAM used %
	HistNetRx map[string][]float64 // per-iface rx bps
	HistNetTx map[string][]float64 // per-iface tx bps
	HistDiskR map[string][]float64 // per-dev read bps (fixed + removable)
	HistDiskW map[string][]float64 // per-dev write bps (fixed + removable)
	HistCtxSw    []float64   // context switches/s
	HistVMsRun   []float64   // total running VMs (all types)
	HistQEMURun  []float64   // running QEMU VMs
	HistVBoxRun  []float64   // running VirtualBox VMs
	HistVMwRun   []float64   // running VMware VMs
	HistDockRun  []float64   // running Docker containers
	HistPodRun   []float64   // running Podman containers
	HistCores    [][]float64 // per-core CPU % history

	HexNetBufs  map[string][]byte
	NetCapMu    sync.Mutex
	traceMu     sync.Mutex
	traceRings  [256][]TraceEntry
	traceMethod string
}

// UI — only touched by main goroutine (no mutex needed)
type UI struct {
	Tab          int
	Interval     time.Duration
	Sel          int    // last-rendered index in visible proc list
	SelPID       int    // PID of selected proc; Sel re-anchors to this each frame
	SelDelta     int    // pending relative movement from key presses
	Scroll       int
	Sort         string
	Filter       string // user | root | kern | all
	CoreOffset   int
	HexSource    int
	HexScroll    int
	HexPID       int
	HexDev       string
	Detail       bool
	DetailPID    int
	DetailTab    int
	DetailScroll int
	Recording      bool
	NetScroll      int
	DevScroll      int
	Search         string
	SearchMode     bool
	HexSel         int    // selected disk or iface index
	HexRegion      int    // selected memory region index
	HexRegScroll   int    // scroll of region list on left pane
	NetLock        bool   // auto-tail net capture (default true)
	HexSearch      string // hex search bytes (space-separated hex like "4d 5a")
	HexSearchMode  bool
	Marked         map[int]bool // marked PIDs (Space key)
	Separators     map[int]bool // PIDs after which a blank separator row is shown (Tab key)
	Frozen         bool         // f=freeze: lock sort order, values still update
	PrevSelPID     int          // PID cursor just left (ghost-leaving effect)
	SelFade        int          // countdown: departure glow (ghost leaving body)
	SelArrive      int          // countdown: arrival flash  (ghost entering body)
}
