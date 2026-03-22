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
		sb.WriteString(dim + " ←→=cores  ↑↓=history  " + RESET)
		sb.WriteString(ansiCol(t.WARN) + "■" + RESET + dim + "=IRQ/miss  " + RESET)
		sb.WriteString(ansiCol(t.DISK) + "■" + RESET + dim + "=normal" + RESET)
}

	full := sb.String()
	clamped := clampVisual(full, cols)
	buf.WriteString(pos(row, 0))
	buf.WriteString(clamped + RESET + CLEOL)
}
