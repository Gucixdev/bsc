package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// startTrace — polls /proc/*/syscall every 50ms
// For each CPU, grabs first PID scheduled there → records syscall name.
// RLE: same syscall as last entry → increment count, else append.
func startTrace(ss *SysState) {
	go func() {
		for {
			time.Sleep(50 * time.Millisecond)

			cpuSyscall := map[int]string{}
			entries, _ := os.ReadDir("/proc")
			for _, e := range entries {
				name := e.Name()
				if len(name) == 0 || name[0] < '0' || name[0] > '9' {
					continue
				}
				stat, err := os.ReadFile("/proc/" + name + "/stat")
				if err != nil {
					continue
				}
				// parse past comm (field 2, in parens)
				j := strings.LastIndexByte(string(stat), ')')
				if j < 0 {
					continue
				}
				rest := strings.Fields(string(stat)[j+2:])
				// rest[36] = processor (field 39 in 1-indexed /proc/PID/stat)
				if len(rest) < 37 {
					continue
				}
				cpu, err := strconv.Atoi(rest[36])
				if err != nil || cpu < 0 || cpu >= 256 {
					continue
				}
				if _, already := cpuSyscall[cpu]; already {
					continue
				}
				scData, err := os.ReadFile("/proc/" + name + "/syscall")
				if err != nil {
					continue
				}
				fields := strings.Fields(string(scData))
				if len(fields) == 0 {
					continue
				}
				if fields[0] == "running" {
					cpuSyscall[cpu] = "running"
					continue
				}
				num, err := strconv.ParseInt(fields[0], 0, 64)
				if err != nil {
					continue
				}
				cpuSyscall[cpu] = syscallName(int(num))
			}

			ss.traceMu.Lock()
			for cpu, sc := range cpuSyscall {
				ring := ss.traceRings[cpu]
				if len(ring) > 0 && ring[len(ring)-1].Syscall == sc {
					ring[len(ring)-1].Count++
				} else {
					ring = append(ring, TraceEntry{Syscall: sc, Count: 1})
					if len(ring) > RING_CAP {
						ring = ring[len(ring)-RING_CAP:]
					}
				}
				ss.traceRings[cpu] = ring
			}
			ss.traceMu.Unlock()
		}
	}()
}

// syscallName — x86_64 syscall number → short name
func syscallName(n int) string {
	switch n {
	case 0: return "read"
	case 1: return "write"
	case 2: return "open"
	case 3: return "close"
	case 4: return "stat"
	case 5: return "fstat"
	case 6: return "lstat"
	case 7: return "poll"
	case 8: return "lseek"
	case 9: return "mmap"
	case 10: return "mprotect"
	case 11: return "munmap"
	case 12: return "brk"
	case 13: return "rt_sigaction"
	case 14: return "rt_sigprocmask"
	case 17: return "pread64"
	case 18: return "pwrite64"
	case 19: return "readv"
	case 20: return "writev"
	case 21: return "access"
	case 22: return "pipe"
	case 23: return "select"
	case 24: return "sched_yield"
	case 28: return "madvise"
	case 32: return "dup"
	case 33: return "dup2"
	case 35: return "nanosleep"
	case 39: return "getpid"
	case 41: return "socket"
	case 42: return "connect"
	case 43: return "accept"
	case 44: return "sendto"
	case 45: return "recvfrom"
	case 46: return "sendmsg"
	case 47: return "recvmsg"
	case 49: return "bind"
	case 50: return "listen"
	case 54: return "setsockopt"
	case 55: return "getsockopt"
	case 56: return "clone"
	case 57: return "fork"
	case 59: return "execve"
	case 60: return "exit"
	case 61: return "wait4"
	case 62: return "kill"
	case 63: return "uname"
	case 72: return "fcntl"
	case 78: return "getdents"
	case 79: return "getcwd"
	case 80: return "chdir"
	case 82: return "rename"
	case 83: return "mkdir"
	case 87: return "unlink"
	case 89: return "readlink"
	case 96: return "gettimeofday"
	case 99: return "sysinfo"
	case 102: return "getuid"
	case 104: return "getgid"
	case 107: return "geteuid"
	case 108: return "getegid"
	case 110: return "getppid"
	case 131: return "sigaltstack"
	case 157: return "prctl"
	case 158: return "arch_prctl"
	case 186: return "gettid"
	case 202: return "futex"
	case 203: return "sched_setaffinity"
	case 204: return "sched_getaffinity"
	case 218: return "set_tid_address"
	case 228: return "clock_gettime"
	case 230: return "clock_nanosleep"
	case 231: return "exit_group"
	case 232: return "epoll_wait"
	case 233: return "epoll_ctl"
	case 234: return "tgkill"
	case 257: return "openat"
	case 262: return "newfstatat"
	case 269: return "faccessat"
	case 270: return "pselect6"
	case 271: return "ppoll"
	case 281: return "epoll_pwait"
	case 283: return "timerfd_create"
	case 288: return "accept4"
	case 291: return "epoll_create1"
	case 292: return "dup3"
	case 293: return "pipe2"
	case 302: return "prlimit64"
	case 318: return "getrandom"
	case 332: return "statx"
	case 334: return "io_uring_setup"
	case 335: return "io_uring_enter"
	}
	return fmt.Sprintf("sc%d", n)
}
