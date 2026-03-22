package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

func pos(row, col int) string    { return fmt.Sprintf("\033[%d;%dH", row+1, col+1) }
func fgRGB(r, g, b uint8) string { return fmt.Sprintf("\033[38;2;%d;%d;%dm", r, g, b) }
func bgRGB(r, g, b uint8) string { return fmt.Sprintf("\033[48;2;%d;%d;%dm", r, g, b) }
func fg256(n int) string         { return fmt.Sprintf("\033[38;5;%dm", n) }
func bg256(n int) string         { return fmt.Sprintf("\033[48;5;%dm", n) }

func bgCol(c Color) string {
	if truecolor {
		return bgRGB(c[0], c[1], c[2])
	}
	ri := (int(c[0])*5 + 127) / 255
	gi := (int(c[1])*5 + 127) / 255
	bi := (int(c[2])*5 + 127) / 255
	return bg256(16 + 36*ri + 6*gi + bi)
}

type Color [3]uint8

type Theme struct {
	HDR, CPU, GPU, RAM, ZRAM, DISK, NET, SEL, USB, MARK, WARN Color
	BG    Color
	HasBG bool
}

var defaultTheme = Theme{
	HDR:  Color{0x77, 0x00, 0xff},
	CPU:  Color{0x99, 0x44, 0xff},
	GPU:  Color{0x00, 0xff, 0x41},
	RAM:  Color{0xff, 0xd7, 0x00},
	ZRAM: Color{0xaf, 0x87, 0xff},
	DISK: Color{0x00, 0xff, 0x41},
	NET:  Color{0x00, 0x87, 0xff},
	SEL:  Color{0xff, 0xff, 0x00},
	USB:  Color{0x77, 0x00, 0xff},
	MARK: Color{0x77, 0x00, 0xff},
	WARN: Color{0xff, 0x00, 0x00},
}

var truecolor bool

func readXResources() map[string]string {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return nil
	}
	out, err := exec.Command("xrdb", "-query").Output()
	if err != nil {
		return nil
	}
	res := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, ":\t")
		if ok {
			res[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return res
}

func xresColor(res map[string]string, keys ...string) (Color, bool) {
	for _, k := range keys {
		v := res[k]
		if len(v) == 7 && v[0] == '#' {
			r, e1 := strconv.ParseUint(v[1:3], 16, 8)
			g, e2 := strconv.ParseUint(v[3:5], 16, 8)
			b, e3 := strconv.ParseUint(v[5:7], 16, 8)
			if e1 == nil && e2 == nil && e3 == nil {
				return Color{uint8(r), uint8(g), uint8(b)}, true
			}
		}
	}
	return Color{}, false
}

func loadTheme() Theme {
	t := defaultTheme

	if xres := readXResources(); xres != nil {
		if c, ok := xresColor(xres, "*.foreground", "*foreground"); ok { t.DISK = c; t.GPU = c }
		if c, ok := xresColor(xres, "*.color1", "*.color9");        ok { t.WARN = c }
		if c, ok := xresColor(xres, "*.color2", "*.color10");       ok { t.GPU = c; t.DISK = c }
		if c, ok := xresColor(xres, "*.color5", "*.color13");       ok { t.HDR = c; t.USB = c; t.MARK = c }
		if c, ok := xresColor(xres, "*.color3", "*.color11");       ok { t.RAM = c; t.SEL = c }
		if c, ok := xresColor(xres, "*.color4", "*.color12");       ok { t.NET = c }
		if c, ok := xresColor(xres, "*.color5", "*.color13");       ok { t.CPU = c }
		if c, ok := xresColor(xres, "*.color6", "*.color14");       ok { t.ZRAM = c }
	}

	path := os.Getenv("HOME") + "/.config/bsc/theme.json"
	f, err := os.Open(path)
	if err != nil {
		return t
	}
	defer f.Close()
	var raw map[string]string
	if json.NewDecoder(f).Decode(&raw) != nil {
		return t
	}
	set := func(dst *Color, key string) {
		v, ok := raw[key]
		if !ok || len(v) != 7 || v[0] != '#' {
			return
		}
		r, _ := strconv.ParseUint(v[1:3], 16, 8)
		g, _ := strconv.ParseUint(v[3:5], 16, 8)
		b, _ := strconv.ParseUint(v[5:7], 16, 8)
		*dst = Color{uint8(r), uint8(g), uint8(b)}
	}
	set(&t.HDR, "HDR"); set(&t.CPU, "CPU"); set(&t.GPU, "GPU")
	set(&t.RAM, "RAM"); set(&t.ZRAM, "ZRAM"); set(&t.DISK, "DISK")
	set(&t.NET, "NET"); set(&t.SEL, "SEL"); set(&t.USB, "USB")
	set(&t.MARK, "MARK"); set(&t.WARN, "WARN")
	if v, ok := raw["BG"]; ok && len(v) == 7 && v[0] == '#' {
		r, _ := strconv.ParseUint(v[1:3], 16, 8)
		g, _ := strconv.ParseUint(v[3:5], 16, 8)
		b, _ := strconv.ParseUint(v[5:7], 16, 8)
		t.BG = Color{uint8(r), uint8(g), uint8(b)}
		t.HasBG = true
	}
	return t
}

func ansiCol(c Color) string {
	if truecolor {
		return fgRGB(c[0], c[1], c[2])
	}
	ri := (int(c[0])*5 + 127) / 255
	gi := (int(c[1])*5 + 127) / 255
	bi := (int(c[2])*5 + 127) / 255
	return fg256(16 + 36*ri + 6*gi + bi)
}

func pctColor(pct float64, t *Theme) Color {
	if pct >= 80 {
		return t.WARN
	}
	if pct >= 50 {
		return t.RAM
	}
	return t.DISK
}

var origT syscall.Termios

func rawOn() {
	syscall.Syscall(syscall.SYS_IOCTL, 0, syscall.TCGETS, uintptr(unsafe.Pointer(&origT)))
	raw := origT
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Iflag &^= syscall.IXON | syscall.ICRNL | syscall.BRKINT | syscall.INPCK | syscall.ISTRIP
	raw.Cflag |= syscall.CS8
	raw.Cc[syscall.VMIN] = 0
	raw.Cc[syscall.VTIME] = 1 // 100ms read timeout
	syscall.Syscall(syscall.SYS_IOCTL, 0, syscall.TCSETS, uintptr(unsafe.Pointer(&raw)))
	os.Stdout.WriteString(HIDECUR)
}

func rawOff() {
	syscall.Syscall(syscall.SYS_IOCTL, 0, syscall.TCSETS, uintptr(unsafe.Pointer(&origT)))
	os.Stdout.WriteString(CLRSCR + HOME + SHOWCUR + "\033[0m")
}

type winsize struct {
	Row, Col       uint16
	Xpixel, Ypixel uint16
}

func winSize() (int, int) {
	var ws winsize
	syscall.Syscall(syscall.SYS_IOCTL, 1, syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	r, c := int(ws.Row), int(ws.Col)
	if r < 1 {
		r = 24
	}
	if c < 1 {
		c = 80
	}
	return r, c
}
