package main

import "time"

const (
	FPS   = 30
	HZ    = 100 // Linux USER_HZ
	FRAME = time.Second / FPS

	TAB_OVW = 0
	TAB_DEV = 1
	TAB_HEX = 2
	TAB_ASM = 3

	DEV_MAIN = 0
	DEV_SEC  = 1
	DEV_OPT  = 2

	SORT_CPU = "cpu"
	SORT_MEM = "mem"

	// TTL cache durations
	GPU_TTL   = 2 * time.Second
	SMART_TTL = 30 * time.Second
	HOOK_TTL  = 5 * time.Second
	VM_TTL    = 8 * time.Second
	AUDIO_TTL = 8 * time.Second
	GHOST_TTL = 5 * time.Second

	// HEX tab sources
	HEX_MEM  = 0
	HEX_DISK = 1
	HEX_NET  = 2
	HEX_VRAM = 3

	RING_CAP = 200
)

const (
	BOLD    = "\033[1m"
	DIM     = "\033[2m"
	REV     = "\033[7m"
	CLRSCR  = "\033[2J"
	HOME    = "\033[H"
	HIDECUR = "\033[?25l"
	SHOWCUR = "\033[?25h"
	SYNCON  = "\033[?2026h"
	SYNCOFF = "\033[?2026l"
	CLEOL   = "\033[K"
)

// RESET is a var so light theme can append bgCol after reset
var RESET = "\033[0m"
