package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func readCtxSwTotal() int64 {
	raw, err := os.ReadFile("/proc/schedstat")
	if err != nil {
		return 0
	}
	var total int64
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "cpu") || strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) > 9 {
			n, _ := strconv.ParseInt(f[9], 10, 64)
			total += n
		}
	}
	return total
}

// buildBoxedRows converts a flat ColLine list (Bold+Title = section boundary)
// into pre-rendered rows with purple box borders.
// Each section: ╭─ title ──╮ / │ content │ / ╰──────────╯ / blank gap.
// Every returned string has exactly colW visible characters.
func buildBoxedRows(lines []ColLine, colW int, t *Theme) []string {
	if colW < 6 {
		colW = 6
	}
	innerW := colW - 2 // space between │ borders

	type section struct {
		title string
		body  []ColLine
	}
	var secs []section
	var cur *section
	for _, l := range lines {
		if l.Bold {
			if cur != nil {
				secs = append(secs, *cur)
			}
			cur = &section{title: l.Title}
		} else if cur != nil {
			cur.body = append(cur.body, l)
		}
	}
	if cur != nil {
		secs = append(secs, *cur)
	}

	border := ansiCol(t.HDR)
	pad := func(s string, w int) string {
		v := visLen(s)
		if v >= w {
			return clampVisual(s, w)
		}
		return s + strings.Repeat(" ", w-v)
	}

	var out []string
	for _, sec := range secs {
		// top border ╭─ title ──────╮
		title := sec.title
		dashes := max(0, innerW-len(title)-4)
		if title != "" {
			out = append(out, border+"╭─ "+title+" "+strings.Repeat("─", dashes)+"╮"+RESET)
		} else {
			out = append(out, border+"╭"+strings.Repeat("─", innerW)+"╮"+RESET)
		}
		// content lines │ … │
		for _, cl := range sec.body {
			var text string
			if cl.Pre {
				text = clampVisual(cl.Text, innerW)
			} else {
				attr := ansiCol(cl.C)
				if cl.Dim {
					attr = DIM + attr
				}
				text = attr + clampStr(cl.Text, innerW) + RESET
			}
			out = append(out, border+"│"+RESET+pad(text, innerW)+border+"│"+RESET)
		}
		// bottom ╰──────╯ + blank gap
		out = append(out, border+"╰"+strings.Repeat("─", innerW)+"╯"+RESET)
		out = append(out, "")
	}
	return out
}

func drawDEV(buf *strings.Builder, rows, cols int, ss *SysState, ui *UI, t *Theme) {
	buf.WriteString(pos(0, 0))
	buf.WriteString(ansiCol(t.HDR) + BOLD + clampStr(" DEV "+strings.Repeat("─", max(0, cols-5)), cols) + RESET + CLEOL)

	divX := cols / 2
	leftW := divX - 1  // left column; 1-char gap before divider
	rightW := cols - divX - 1 // right column; 1-char gap after divider
	if leftW < 10 {
		leftW = 10
	}
	if rightW < 10 {
		rightW = 10
	}

	// purple divider — full height
	for r := 1; r < rows-1; r++ {
		buf.WriteString(pos(r, divX))
		buf.WriteString(ansiCol(t.HDR) + "│" + RESET)
	}

	secLines := buildSecLines(ss, ui, t)
	optLines, _ := bgOPT.get(collectOPT)

	secRows := buildBoxedRows(secLines, leftW, t)
	optRows := buildBoxedRows(optLines, rightW, t)

	displayRows := rows - 2 // row 0=hdr, rows-1=statusbar
	maxH := max(len(secRows), len(optRows))
	maxScroll := max(0, maxH-displayRows)
	if ui.SecScroll > maxScroll {
		ui.SecScroll = maxScroll
	}

	for r := 0; r < displayRows; r++ {
		si := ui.SecScroll + r
		buf.WriteString(pos(r+1, 0))

		// left: SEC
		if si < len(secRows) {
			vl := visLen(secRows[si])
			buf.WriteString(secRows[si] + strings.Repeat(" ", max(0, leftW-vl)))
		} else {
			buf.WriteString(strings.Repeat(" ", leftW))
		}

		// right: OPT (after divider at divX)
		buf.WriteString(pos(r+1, divX+1))
		if si < len(optRows) {
			buf.WriteString(optRows[si])
		}
		buf.WriteString(CLEOL)
	}

	pct := 0
	if maxH > 0 {
		pct = (ui.SecScroll + displayRows/2) * 100 / maxH
	}
	fmt.Fprintf(buf, "%s%s %d%%%s%s", pos(rows-2, 0), DIM+ansiCol(t.USB), pct, RESET, CLEOL)

	drawStatusBar(buf, rows, cols, ui, ui.Interval, ss, t)
}
