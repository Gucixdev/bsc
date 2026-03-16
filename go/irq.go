package main

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
)

var prevIRQRaw map[string]int64

func readIRQs() []IRQDelta {
	f, err := os.Open("/proc/interrupts")
	if err != nil {
		return nil
	}
	defer f.Close()

	cur := map[string]int64{}
	sc := bufio.NewScanner(f)
	sc.Scan() // header CPU0 CPU1 ...
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		// count numeric per-cpu fields
		i := 1
		var total int64
		for i < len(fields) {
			v, err := strconv.ParseInt(fields[i], 10, 64)
			if err != nil {
				break
			}
			total += v
			i++
		}
		// name: remaining fields after counts; fallback to irq number
		name := strings.TrimSuffix(fields[0], ":")
		if i < len(fields) {
			tail := strings.Join(fields[i:], " ")
			if len(tail) > 28 {
				tail = tail[:28]
			}
			name = tail
		}
		cur[name] += total
	}

	var result []IRQDelta
	for name, count := range cur {
		delta := int64(0)
		if prevIRQRaw != nil {
			if d := count - prevIRQRaw[name]; d > 0 {
				delta = d
			}
		}
		result = append(result, IRQDelta{Name: name, Count: count, Delta: delta})
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Delta > result[j].Delta
	})

	prevIRQRaw = cur
	return result
}
