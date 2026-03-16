package main

import "strings"

// drawHints — color legend only; keyboard shortcuts are in the statusbar
func drawHints(buf *strings.Builder, row, cols int, ui *UI, t *Theme) {
	var sb strings.Builder
	dim := DIM + ansiCol(t.USB)

	switch ui.Tab {
	case TAB_OVW:
		sb.WriteString(dim + " " + RESET)
		sb.WriteString(ansiCol(t.RAM) + "■" + RESET + dim + "=med  " + RESET)
		sb.WriteString(ansiCol(t.WARN) + "■" + RESET + dim + "=high/unavail  " + RESET)
		sb.WriteString(ansiCol(t.DISK) + "■" + RESET + dim + "=ok  " + RESET)
		sb.WriteString(ansiCol(t.USB) + "■" + DIM + "=kern" + RESET)
	case TAB_DEV:
		// mem map inline labels are self-explanatory; warn color = missing flag
		sb.WriteString(dim + " warn=missing CPU flag  " + RESET)
		sb.WriteString(ansiCol(t.WARN) + "■" + RESET + dim + "=IRQ spike  " + RESET)
		sb.WriteString(ansiCol(t.DISK) + "■" + RESET + dim + "=normal" + RESET)
}

	full := sb.String()
	clamped := clampVisual(full, cols)
	buf.WriteString(pos(row, 0))
	buf.WriteString(clamped + RESET + CLEOL)
}
