package main

import (
	"fmt"
	"strings"
	"time"
)

func fmtUptime(secs int64) string {
	d := secs / 86400
	secs %= 86400
	h := secs / 3600
	secs %= 3600
	m := secs / 60
	s := secs % 60
	if d > 0 {
		return fmt.Sprintf("%dd %02d:%02d:%02d", d, h, m, s)
	}
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func drawStatusBar(buf *strings.Builder, rows, cols int, ui *UI, interval time.Duration, ss *SysState, t *Theme) {
	global := "q Tab=cycle +/-=ms R=rec"
	if ui.Recording {
		global += " [REC]"
	}
	var local string
	switch ui.Tab {
	case TAB_OVW:
		local = " | ↑↓=sel ←→=filter c/m=sort f=freeze k=kill y=pid Y=cmd Space=mark"
		if ui.Frozen {
			local += " [FROZEN]"
		}
	case TAB_DEV:
		local = " | ↑↓=scroll ←→=cores"
	case TAB_SEC:
		local = " | ↑↓=scroll"
	case TAB_HEX:
		srcName := [3]string{"MEM", "DISK", "NET"}[ui.HexSource]
		local = fmt.Sprintf(" | ↑↓=scroll ←→=sel w=src l=lock /=search  src:%s", srcName)
		if ui.HexSource == HEX_NET && ui.NetLock {
			local += " [LOCK]"
		}
	}
	left := global + local

	ss.mu.RLock()
	batt := ss.Battery
	uptime := ss.Uptime
	ss.mu.RUnlock()

	batS := "no bat"
	if batt.Pct > 0 || batt.Charging {
		arrow := "="
		if batt.Charging {
			arrow = "+"
		} else if !batt.Full {
			arrow = "-"
		}
		batS = fmt.Sprintf("BAT:%d%%%s", batt.Pct, arrow)
	}

	upS := fmtUptime(uptime)
	date := time.Now().Format("2006-01-02 15:04")
	right := fmt.Sprintf("├ %s | up:%s | %s | %dms ─┤", batS, upS, date, interval.Milliseconds())

	gap := cols - len(left) - len(right) - 2
	if gap < 1 {
		gap = 1
	}
	bar := " " + left + strings.Repeat(" ", gap) + right
	runes := []rune(bar)
	if len(runes) > cols {
		bar = string(runes[:cols])
	} else {
		bar = bar + strings.Repeat(" ", cols-len(runes))
	}

	buf.WriteString(pos(rows-1, 0))
	buf.WriteString(REV + bar + RESET)
}
