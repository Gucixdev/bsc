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
	var left string
	switch ui.Tab {
	case TAB_OVW:
		left = "OVW  ↑↓ ←→filter  c/m=sort  f=frz  k=kill  spc=mark  y=pid"
		if ui.Frozen {
			left += "  [FRZ]"
		}
	case TAB_DEV:
		pages := [3]string{"MAIN", "SEC", "OPT"}
		left = fmt.Sprintf("DEV[%s]  ↑↓  Alt=page", pages[ui.DevPage])
		if ui.DevPage == DEV_MAIN {
			left += "  ←→=threads"
		}
	case TAB_HEX:
		srcName := [4]string{"MEM", "DISK", "NET", "VRAM"}[ui.HexSource]
		skipMark := ""
		if ui.HexSkipZero {
			skipMark = "  [0skip]"
		}
		left = fmt.Sprintf("HEX[%s]  ↑↓  Alt=src  ←→=sel  /=search  z=0skip%s", srcName, skipMark)
		if ui.HexSource == HEX_NET && ui.NetLock {
			left += "  [LOCK]"
		}
	case TAB_ASM:
		left = "ASM  ↑↓  ←→=pid  n/N=fn  p=sel  g=top  Alt=src"
	}

	flags := ""
	if ui.Recording {
		flags += " REC"
	}
	if ui.Anon {
		flags += " ANON"
	}
	if flags != "" {
		left += " [" + flags[1:] + "]"
	}

	ss.mu.RLock()
	batt := ss.Battery
	uptime := ss.Uptime
	ss.mu.RUnlock()

	batS := ""
	if batt.Pct > 0 || batt.Charging {
		arrow := "="
		if batt.Charging {
			arrow = "↑"
		} else if !batt.Full {
			arrow = "↓"
		}
		batS = fmt.Sprintf(" %d%%%s", batt.Pct, arrow)
	}

	spin := ""
	if anyBgLoading() {
		spin = spinChar() + " "
	}

	right := fmt.Sprintf("%sup%s%s %s %dms",
		spin,
		fmtUptime(uptime),
		batS,
		time.Now().Format("15:04"),
		interval.Milliseconds(),
	)

	// use rune count to handle Unicode arrows correctly
	leftW := len([]rune(left))
	rightW := len([]rune(right))
	gap := cols - leftW - rightW - 2
	if gap < 1 {
		gap = 1
	}

	bar := " " + left + strings.Repeat(" ", gap) + right + " "
	runes := []rune(bar)
	if len(runes) > cols {
		bar = string(runes[:cols])
	} else if len(runes) < cols {
		bar = bar + strings.Repeat(" ", cols-len(runes))
	}

	buf.WriteString(pos(rows-1, 0))
	buf.WriteString(REV + bar + RESET)
}
