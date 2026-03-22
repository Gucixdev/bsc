package main

import (
	"fmt"
	"os"
	"time"
)

var recFile *os.File
var lastRecordAt time.Time

func toggleRecording(ui *UI) {
	if ui.Recording {
		ui.Recording = false
		if recFile != nil {
			recFile.Close()
			recFile = nil
		}
		return
	}
	dir := os.Getenv("HOME") + "/.local/share/bsc"
	_ = os.MkdirAll(dir, 0755)
	name := dir + "/" + time.Now().Format("20060102-150405") + ".tsv"
	f, err := os.Create(name)
	if err != nil {
		return
	}
	fmt.Fprintf(f, "# bsc record — started %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(f, "time\tpid\tcomm\tcpu%%\tmemKB\tstate\n")
	recFile = f
	lastRecordAt = time.Time{} // force immediate first write
	ui.Recording = true
}

// writeRecord — called from render loop; writes one snapshot per collect interval
func writeRecord(ss *SysState, interval time.Duration) {
	if recFile == nil {
		return
	}
	if time.Since(lastRecordAt) < interval {
		return
	}
	lastRecordAt = time.Now()
	ts := lastRecordAt.Format("15:04:05")
	ss.mu.RLock()
	procs := ss.Procs
	ss.mu.RUnlock()
	limit := 10
	if len(procs) < limit {
		limit = len(procs)
	}
	for _, p := range procs[:limit] {
		fmt.Fprintf(recFile, "%s\t%d\t%s\t%.1f\t%d\t%s\n",
			ts, p.PID, p.Comm, p.CPU, p.MemKB, p.State)
	}
}
