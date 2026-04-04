package main

import (
	"fmt"
	"strings"
	"time"
)

// kb renders a keyboard key as a visual "button" inside the reversed status bar.
// RESET within REV context creates a normal-video island — looks like a raised key.
func kb(sym string) string {
	return RESET + BOLD + " " + sym + " " + REV
}

// visLen counts visible columns in s, skipping ANSI escape sequences.
func visLen(s string) int {
	n, i := 0, 0
	for i < len(s) {
		if s[i] == '\033' {
			j := i + 1
			if j < len(s) && s[j] == '[' {
				j++
				for j < len(s) && !((s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= 'a' && s[j] <= 'z')) {
					j++
				}
				if j < len(s) {
					j++
				}
			}
			i = j
			continue
		}
		if s[i]&0xC0 != 0x80 { // rune-start byte only
			n++
		}
		i++
	}
	return n
}

func fmtUptime(secs int64) string {
	d := secs / 86400
	secs %= 86400
	h := secs / 3600
	secs %= 3600
	m := secs / 60
	s := secs % 60
	if d > 0 {
		return fmt.Sprintf("%dd%02d:%02d:%02d", d, h, m, s)
	}
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func drawStatusBar(buf *strings.Builder, rows, cols int, ui *UI, interval time.Duration, ss *SysState, t *Theme) {
	var left string
	switch ui.Tab {
	case TAB_OVW:
		left = "OVW " +
			kb("↑") + kb("↓") + " nav " +
			kb("←") + kb("→") + " filter " +
			kb("c") + kb("m") + " sort " +
			kb("f") + " freeze " +
			kb("k") + " kill " +
			kb("␣") + " mark " +
			kb("y") + " pid"
		if ui.Frozen {
			left += " [FRZ]"
		}
	case TAB_DEV:
		left = "DEV " +
			kb("↑") + kb("↓") + " scroll " +
			kb("Esc") + " top " +
			kb("⇥") + " tab"
	case TAB_HEX:
		srcName := [4]string{"MEM", "DISK", "NET", "VRAM"}[ui.HexSource]
		left = "HEX·" + srcName + " " +
			kb("↑") + kb("↓") + " scroll " +
			kb("Esc") + " src " +
			kb("⇥") + " tab " +
			kb("←") + kb("→") + " sel " +
			kb("/") + " search " +
			kb("z") + " 0skip"
		if ui.HexSkipZero {
			left += "●"
		}
		if ui.HexSource == HEX_NET && ui.NetLock {
			left += " " + kb("l") + "LOCK"
		}
	case TAB_ASM:
		left = "ASM " +
			kb("↑") + kb("↓") + " scroll " +
			kb("←") + kb("→") + " pid " +
			kb("n") + kb("N") + " fn " +
			kb("/") + " search " +
			kb("g") + " top " +
			kb("Esc") + " src"
	}

	flags := ""
	if ui.Recording {
		flags += " ⏺REC"
	}
	if ui.Anon {
		flags += " ANON"
	}
	if flags != "" {
		left += " [" + strings.TrimPrefix(flags, " ") + "]"
	}

	ss.mu.RLock()
	batt := ss.Battery
	uptime := ss.Uptime
	ss.mu.RUnlock()

	batS := ""
	if batt.Pct > 0 || batt.Charging {
		icon := "↓"
		if batt.Charging {
			icon = "↑"
		} else if batt.Full {
			icon = "="
		}
		batS = fmt.Sprintf(" %d%%%s", batt.Pct, icon)
		if !batt.Charging && !batt.Full && batt.Watts > 0.1 {
			batS += fmt.Sprintf(" %.1fW", batt.Watts)
		}
	}

	spin := ""
	if anyBgLoading() {
		spin = spinChar() + " "
	}

	right := fmt.Sprintf("%s%s%s %s %dms",
		spin,
		fmtUptime(uptime),
		batS,
		time.Now().Format("15:04"),
		interval.Milliseconds(),
	)

	lw := visLen(left)
	rw := visLen(right)
	gap := cols - lw - rw - 2
	if gap < 1 {
		gap = 1
	}

	// Build bar: REV context, with key buttons as RESET islands
	var b strings.Builder
	b.WriteString(REV)
	b.WriteByte(' ')
	b.WriteString(left)
	b.WriteString(strings.Repeat(" ", gap))
	b.WriteString(right)
	b.WriteByte(' ')
	b.WriteString(RESET)
	bar := b.String()

	plainLen := lw + rw + gap + 2
	if plainLen < cols {
		// insert extra padding before RESET at end
		bar = bar[:len(bar)-len(RESET)] + strings.Repeat(" ", cols-plainLen) + RESET
	}

	buf.WriteString(pos(rows-1, 0))
	buf.WriteString(bar)
}
