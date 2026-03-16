package main

import (
	"fmt"
	"os"
	"time"
)

var recFile *os.File

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
	recFile = f
	ui.Recording = true
}
