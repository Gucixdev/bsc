package main

import (
	"sync"
	"time"
)

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

type SysState struct {
	mu          sync.RWMutex
	Ghosts      map[int]GhostProc
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
	HistCPU      []float64
	HistGPU      []float64
	HistVRAM     []float64
	HistNetRx    map[string][]float64
	HistNetTx    map[string][]float64
	HistDiskR    map[string][]float64
	HistDiskW    map[string][]float64
	HistCtxSw    []float64
	HistVMsRun   []float64
	HistQEMURun  []float64
	HistVBoxRun  []float64
	HistVMwRun   []float64
	HistDockRun  []float64
	HistPodRun   []float64
	HistCores    [][]float64

	HexNetBufs   map[string][]byte
	NetCapMu     sync.Mutex
	traceMu      sync.Mutex
	threadRings  map[int][]TraceEntry
	threadComms  map[int]string
	threadPIDs   map[int]int // TID -> PID
}

type UI struct {
	Tab          int
	Interval     time.Duration
	Sel          int
	SelPID       int
	SelDelta     int
	Scroll       int
	Sort         string
	Filter       string
	CoreOffset   int
	TraceNCols   int // set by drawDEV; used by key handler for page jumps
	HexSource    int
	HexScroll    int
	HexPID       int
	HexDev       string
	Detail       bool
	DetailPID    int
	DetailTab    int
	DetailScroll int
	Recording    bool
	NetScroll    int
	DevScroll    int
	SecScroll    int
	Search       string
	SearchMode   bool
	HexSel       int
	HexRegion    int
	HexRegScroll int
	NetLock      bool
	HexSearch    string
	HexSearchMode bool
	Marked         map[int]bool
	Separators     map[int]bool
	Frozen         bool
	Anon           bool
	PrevSelPID     int
	SelFade        int
	SelArrive      int
	AsmPID         int
	AsmScroll      int
}
