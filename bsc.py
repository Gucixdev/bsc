#!/usr/bin/env python3
# bsc — system monitor v1 gucixdev
# 3 tabs: 0=OVW+PRC 1=DEV 2=HEX
# q=quit Tab=next tab Shift+Tab=prev +/-=interval ↑↓=scroll R=record
# devlog: rewrite of sysmon — split col_mem_gpu→col_ram+col_gpu, hex tab, recording; removed graph tab

import curses, time, os, re, subprocess, socket, struct, fcntl, ctypes, collections, sys, argparse, shutil, threading, select

C_HDR=1; C_CPU=2; C_GPU=3; C_RAM=4; C_ZRAM=5; C_DISK=6; C_NET=7; C_SEL=8; C_USB=9
C_MARK=10; C_WARN=11

def _hex_to_256(h):
    # convert #RRGGBB → nearest xterm-256 index
    # supports truecolor init if terminal has COLORS >= 2^24
    h = h.lstrip('#')
    r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
    # try truecolor first (ncurses extended color, Python 3.10+, needs $COLORTERM=truecolor)
    if hasattr(curses, 'init_extended_color') and curses.COLORS >= 16777216:
        # pick a free slot above 255
        _hex_to_256._slot = getattr(_hex_to_256, '_slot', 256)
        slot = _hex_to_256._slot; _hex_to_256._slot += 1
        try:
            curses.init_extended_color(slot, r*1000//255, g*1000//255, b*1000//255)
            return slot
        except: pass
    # fallback: nearest color in xterm 6x6x6 cube (indices 16-231)
    ri = round(r / 255 * 5)
    gi = round(g / 255 * 5)
    bi = round(b / 255 * 5)
    cube = 16 + 36*ri + 6*gi + bi
    # also check grayscale ramp (232-255): 8,18,28...238
    lum = (r*299 + g*587 + b*114) // 1000
    gray = 232 + round((lum - 8) / 10) if lum >= 8 else 232
    gray = max(232, min(255, gray))
    return cube

def _load_theme():
    import json
    path = os.path.expanduser('~/.config/bsc/theme.json')
    try:
        raw = json.load(open(path))
        # accept both #RRGGBB hex strings and plain xterm-256 integers
        return {k: _hex_to_256(v) if isinstance(v, str) and v.startswith('#') else v
                for k, v in raw.items()}
    except:
        return {}

GPU_TTL   = 2.0
SMART_TTL = 30.0
HOOK_TTL  = 5.0

KERN_RE = re.compile(
    r'^\[|^kworker|^ksoftirqd|^migration/|^idle_inject|^cpuhp/'
    r'|^rcu_|^watchdog/|^kswapd|^khugepaged|^kcompactd|^kblockd'
    r'|^scsi_|^irq/|^jbd2/|^kthread$|^rcuop|^rcub|^kauditd|^kdevtmpfs'
    r'|^bioset|^kstrp|^inet_frag|^nfsiod|^rpciod|^xprtiod'
)

FILTER_MODES = ['user', 'root', 'kern', 'all']

SKIP_FS = {'proc','sysfs','devtmpfs','tmpfs','cgroup','cgroup2','pstore',
           'efivarfs','securityfs','debugfs','tracefs','hugetlbfs','mqueue',
           'fusectl','binfmt_misc','overlay','autofs','ramfs','squashfs'}

_gpu_cache    = (0.0, {})
_nvml_lib     = None   # None=untried, object()=failed, CDLL=ok
_nvml_ok      = False
_smart_cache  = {}
_prev_cpu     = None
_prev_disk    = {}
_prev_net     = {}
_prev_proc    = {}
_rapl_prev    = (0, 0.0)
_wifi_cache   = {}
_hook_cache   = {}
_gw_cache     = (0.0, '')
_ping_cache   = {}
_pubip_cache  = (0.0, '')
_pubip_proc   = None
_pubip_srv_idx = 0
_conns_cache  = (0.0, {})
_prev_dev     = {}
_prev_ring_len = {}   # core_n → ring length at last draw, used for scroll anchoring


# per-core syscall ring: core_n (int) -> deque of "pid:comm  syscall(args) [×N]"
_core_rings          = {}
_core_sampler_thread = None
_core_sampler_run    = False
_core_watch          = 0   # which core to sample right now

# eBPF backend (bpftrace) — optional, needs CAP_BPF or root
_bpf_proc        = None
_bpf_core_active = -1

# perf trace backend — optional, needs perf + perf_event_paranoid<=2
_perf_proc        = None
_perf_core_active = -1
_perf_buf         = b''

def _ensure_bpf():
    # Single system-wide bpftrace — no cpu filter, routes events to per-core rings.
    # Format: cpu\tpid\tcomm\tsyscall_nr
    global _bpf_proc
    if _bpf_proc and _bpf_proc.poll() is None:
        return _bpf_proc
    if _bpf_proc:
        try: _bpf_proc.kill()
        except: pass
        _bpf_proc = None
    if not shutil.which('bpftrace'):
        return None
    try:
        prog = ("tracepoint:raw_syscalls:sys_enter "
                "{ printf(\"%d\\t%d\\t%s\\t%d\\n\", cpu, pid, comm, args->id); }")
        _bpf_proc = subprocess.Popen(
            ['bpftrace', '-e', prog],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        fl = fcntl.fcntl(_bpf_proc.stdout.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(_bpf_proc.stdout.fileno(), fcntl.F_SETFL, fl | os.O_NONBLOCK)
        return _bpf_proc
    except:
        _bpf_proc = None
        return None


# ── helpers ────────────────────────────────────────────────────────────────

def fb(n):
    for u in ('B','K','M','G','T'):
        if abs(n) < 1024: return f"{n:.0f}{u}"
        n /= 1024
    return f"{n:.0f}P"

def fmt_mem(kb):
    if kb >= 1048576: return f"{kb/1048576:.1f}G"
    if kb >= 1024:    return f"{kb//1024}M"
    return f"{kb}K"

def kbs(kb): return fmt_mem(kb)

def pct2(used, tot): return 0 if not tot else min(100, 100*used//tot)

def put(win, y, x, s, attr=0):
    try:
        mh, mw = win.getmaxyx()
        if 0 <= y < mh and 0 <= x < mw:
            win.addstr(y, x, s[:mw-x], attr)
    except: pass

def _refresh(w):
    # synchronized update — terminal renders the full frame atomically (no tearing)
    # terminals that don't support it silently ignore the unknown escape sequences
    os.write(1, b'\033[?2026h')  # DEC private: begin synchronized update
    w.noutrefresh()
    curses.doupdate()            # all curses output lands on fd 1 here
    os.write(1, b'\033[?2026l') # end synchronized update → terminal paints

# ── CPU ────────────────────────────────────────────────────────────────────

def read_cpu():
    global _prev_cpu
    try:
        lines = open('/proc/stat').readlines()
    except:
        return [], (0.0, 0.0, 0.0), 0
    cur = []
    for l in lines:
        if not l.startswith('cpu') or l.startswith('cpu '): continue
        cur.append(list(map(int, l.split()[1:8])))
    pcts = []
    if _prev_cpu and len(_prev_cpu) == len(cur):
        for p, n in zip(_prev_cpu, cur):
            idle_d = n[3]-p[3]; tot_d = sum(n)-sum(p)
            pcts.append(0.0 if tot_d == 0 else 100*(1-idle_d/tot_d))
    else:
        pcts = [0.0] * len(cur)
    _prev_cpu = cur
    temps = {}
    try:
        for hw in os.listdir('/sys/class/hwmon'):
            b = f'/sys/class/hwmon/{hw}'
            try:
                if open(f'{b}/name').read().strip() != 'coretemp': continue
            except: continue
            for f in os.listdir(b):
                m = re.match(r'temp(\d+)_label', f)
                if not m: continue
                try:
                    lbl = open(f'{b}/{f}').read().strip()
                    cm = re.match(r'Core (\d+)', lbl)
                    if cm:
                        temps[int(cm.group(1))] = int(open(f'{b}/temp{m.group(1)}_input').read())//1000
                except: pass
    except: pass
    freqs = {}
    try:
        for cpu in os.listdir('/sys/devices/system/cpu'):
            m = re.match(r'cpu(\d+)$', cpu)
            if not m: continue
            try:
                freqs[int(m.group(1))] = int(open(
                    f'/sys/devices/system/cpu/{cpu}/cpufreq/scaling_cur_freq').read())//1000
            except: pass
    except: pass
    base_freqs = {}
    try:
        for cpu in os.listdir('/sys/devices/system/cpu'):
            m2 = re.match(r'cpu(\d+)$', cpu)
            if not m2: continue
            try:
                base_freqs[int(m2.group(1))] = int(open(
                    f'/sys/devices/system/cpu/{cpu}/cpufreq/base_frequency').read()) // 1000
            except: pass
    except: pass
    throttles = {}
    try:
        for cpu in os.listdir('/sys/devices/system/cpu'):
            m2 = re.match(r'cpu(\d+)$', cpu)
            if not m2: continue
            try:
                throttles[int(m2.group(1))] = int(open(
                    f'/sys/devices/system/cpu/{cpu}/thermal_throttle/core_throttle_count').read())
            except: pass
    except: pass
    cores = []
    for i, p in enumerate(pcts):
        t      = temps.get(i, temps.get(i // 2, 0))
        cur_f  = freqs.get(i, 0)
        base_f = base_freqs.get(i, 0)
        cores.append({'pct': p, 'freq': cur_f, 'temp': t,
                      'is_turbo': cur_f > 0 and base_f > 0 and cur_f > base_f,
                      'throttle': throttles.get(i, 0)})
    try:
        load = tuple(float(x) for x in open('/proc/loadavg').read().split()[:3])
    except:
        load = (0.0, 0.0, 0.0)
    rapl = 0
    try:
        rapl = int(open('/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj').read())
    except: pass
    return cores, load, rapl

# ── GPU ────────────────────────────────────────────────────────────────────

GPU_HWMON_NAMES = {'nouveau', 'amdgpu', 'i915'}

def _gpu_smi():
    try:
        out = subprocess.check_output(
            ['nvidia-smi', '--query-gpu=name,utilization.gpu,temperature.gpu,'
             'memory.used,memory.total,power.draw,driver_version,fan.speed,'
             'memory.bandwidth.tx,memory.bandwidth.rx',
             '--format=csv,noheader,nounits'],
            timeout=2, stderr=subprocess.DEVNULL
        ).decode().strip().split(',')
        def _i(idx, default=0):
            try: return int(out[idx])
            except: return default
        def _f(idx, default=0.0):
            try: return float(out[idx])
            except: return default
        def _s(idx, default=''):
            return out[idx].strip() if idx < len(out) else default
        return {
            'model':    _s(0).replace('NVIDIA GeForce ', '').replace('NVIDIA ', ''),
            'util':     _i(1),
            'temp':     _i(2),
            'mem_used': _i(3),
            'mem_tot':  _i(4),
            'power':    _f(5),
            'driver':   _s(6),
            'fan':      _i(7, -1),
            'bw_tx':    _i(8, -1),
            'bw_rx':    _i(9, -1),
            'source':   'smi',
        }
    except:
        return {}

def _nvml_init():
    global _nvml_lib, _nvml_ok
    if _nvml_ok: return True
    if _nvml_lib is not None: return False
    try:
        lib = ctypes.CDLL('libnvidia-ml.so.1')
        if lib.nvmlInit_v2() != 0: raise RuntimeError
        _nvml_lib = lib; _nvml_ok = True; return True
    except:
        _nvml_lib = object()
        return False

def _gpu_nvml():
    if not _nvml_init(): return {}
    lib = _nvml_lib
    try:
        handle = ctypes.c_void_p()
        if lib.nvmlDeviceGetHandleByIndex_v2(0, ctypes.byref(handle)) != 0: return {}
        name_buf = ctypes.create_string_buffer(96)
        lib.nvmlDeviceGetName(handle, name_buf, 96)
        model = name_buf.value.decode().replace('NVIDIA GeForce ', '').replace('NVIDIA ', '')
        class NvmlUtil(ctypes.Structure):
            _fields_ = [('gpu', ctypes.c_uint), ('memory', ctypes.c_uint)]
        u = NvmlUtil()
        lib.nvmlDeviceGetUtilizationRates(handle, ctypes.byref(u))
        temp = ctypes.c_uint()
        lib.nvmlDeviceGetTemperature(handle, 0, ctypes.byref(temp))
        class NvmlMem(ctypes.Structure):
            _fields_ = [('total', ctypes.c_ulonglong),
                        ('free',  ctypes.c_ulonglong),
                        ('used',  ctypes.c_ulonglong)]
        m = NvmlMem()
        lib.nvmlDeviceGetMemoryInfo(handle, ctypes.byref(m))
        power_mw = ctypes.c_uint()
        lib.nvmlDeviceGetPowerUsage(handle, ctypes.byref(power_mw))
        return {
            'model':    model,
            'util':     u.gpu,
            'temp':     temp.value,
            'mem_used': m.used  >> 20,
            'mem_tot':  m.total >> 20,
            'power':    power_mw.value / 1000.0,
            'source':   'nvml',
        }
    except: return {}

def _gpu_nvidia_proc():
    try:
        gpus = os.listdir('/proc/driver/nvidia/gpus')
    except:
        return {}
    if not gpus: return {}
    data = {'source': 'nvidia-proc'}
    try:
        info = open(f'/proc/driver/nvidia/gpus/{gpus[0]}/information').read()
        m = re.search(r'Model:\s*(.+)', info)
        if m:
            data['model'] = m.group(1).strip().replace('NVIDIA GeForce ','').replace('NVIDIA ','')
    except: pass
    try:
        data['driver'] = open('/sys/module/nvidia/version').read().strip()
    except: pass
    try:
        for hw in os.listdir('/sys/class/hwmon'):
            b = f'/sys/class/hwmon/{hw}'
            name = open(f'{b}/name').read().strip()
            if name == 'nvidia':
                data['temp'] = int(open(f'{b}/temp1_input').read()) // 1000
                break
    except: pass
    return data

def _gpu_hwmon():
    try:
        for hw in sorted(os.listdir('/sys/class/hwmon')):
            b = f'/sys/class/hwmon/{hw}'
            try:
                name = open(f'{b}/name').read().strip()
            except: continue
            if name not in GPU_HWMON_NAMES: continue
            data = {'model': name.upper(), 'source': 'hwmon'}
            try: data['temp'] = int(open(f'{b}/temp1_input').read()) // 1000
            except: pass
            try: data['power'] = int(open(f'{b}/power1_average').read()) / 1e6
            except: pass
            try:
                base = os.path.realpath(b)
                used  = int(open(f'{base}/../mem_info_vram_used').read())
                total = int(open(f'{base}/../mem_info_vram_total').read())
                data['mem_used'] = used >> 20
                data['mem_tot']  = total >> 20
            except: pass
            # AMD: gpu_busy_percent — simplest, no deps, works with amdgpu driver
            if name == 'amdgpu':
                try:
                    for card in sorted(os.listdir('/sys/class/drm')):
                        bp = f'/sys/class/drm/{card}/device/gpu_busy_percent'
                        if os.path.exists(bp):
                            data['util'] = int(open(bp).read().strip())
                            break
                except: pass
            return data
    except: pass
    return {}

def _gpu_rocm():
    # AMD ROCm smi fallback — only if rocm-smi binary exists
    try:
        out = subprocess.check_output(
            ['rocm-smi', '-a', '--json'],
            timeout=3, stderr=subprocess.DEVNULL
        ).decode()
        # parse minimal JSON without json module — find GPU usage, temp, power
        util  = re.search(r'"GPU use \(\%\)"\s*:\s*"(\d+)"', out)
        temp  = re.search(r'"Temperature \(Sensor edge\) \(C\)"\s*:\s*"([\d.]+)"', out)
        power = re.search(r'"Average Graphics Package Power \(W\)"\s*:\s*"([\d.]+)"', out)
        mused = re.search(r'"VRAM Total Used Memory \(B\)"\s*:\s*"(\d+)"', out)
        mtot  = re.search(r'"VRAM Total Memory \(B\)"\s*:\s*"(\d+)"', out)
        if not util: return {}
        data = {'model': 'AMD GPU', 'source': 'rocm'}
        if util:   data['util']     = int(util.group(1))
        if temp:   data['temp']     = int(float(temp.group(1)))
        if power:  data['power']    = float(power.group(1))
        if mused:  data['mem_used'] = int(mused.group(1)) >> 20
        if mtot:   data['mem_tot']  = int(mtot.group(1))  >> 20
        return data
    except:
        return {}

def read_gpu():
    global _gpu_cache
    ts, data = _gpu_cache
    if time.time() - ts < GPU_TTL: return data
    data = _gpu_smi() or _gpu_nvml() or _gpu_nvidia_proc() or _gpu_hwmon() or _gpu_rocm()
    _gpu_cache = (time.time(), data)
    return data

# ── RAM ────────────────────────────────────────────────────────────────────

def read_mem():
    mi = {}
    try:
        for l in open('/proc/meminfo'):
            k, v = l.split(':'); mi[k.strip()] = int(v.split()[0])
    except: return {}
    zt = zu = 0
    try:
        zt = int(open('/sys/block/zram0/disksize').read()) >> 10
        zu = int(open('/sys/block/zram0/mm_stat').read().split()[1]) >> 10
    except: pass
    return {
        'total':     mi.get('MemTotal', 0),
        'used':      mi.get('MemTotal', 0) - mi.get('MemAvailable', 0),
        'swap_tot':  mi.get('SwapTotal', 0),
        'swap_used': mi.get('SwapTotal', 0) - mi.get('SwapFree', 0),
        'zram_tot':  zt, 'zram_used': zu,
    }

# ── DISK ───────────────────────────────────────────────────────────────────

def _disk_parent(part):
    m = re.match(r'(sd[a-z])\d+$', part)
    if m: return m.group(1)
    m = re.match(r'(nvme\d+n\d+)p\d+$', part)
    if m: return m.group(1)
    m = re.match(r'(vd[a-z])\d+$', part)
    if m: return m.group(1)
    m = re.match(r'(mmcblk\d+)p\d+$', part)
    if m: return m.group(1)
    return None

def read_mounts():
    result = {}
    try:
        for l in open('/proc/mounts'):
            p = l.split()
            if len(p) < 3: continue
            dev, mp, fs = p[0], p[1], p[2]
            if fs in SKIP_FS: continue
            m = re.match(r'/dev/(sd[a-z]\d+|nvme\d+n\d+p\d+|vd[a-z]\d+|mmcblk\d+p\d+)$', dev)
            if not m: continue
            part = m.group(1)
            if part in result: continue
            try:
                st = os.statvfs(mp)
                total = st.f_blocks * st.f_frsize
                avail = st.f_bavail * st.f_frsize
                result[part] = {'mp': mp, 'used': total - avail, 'total': total, 'fs': fs}
            except: pass
    except: pass
    return result

def _disk_is_removable(dev):
    # USB drives, card readers, optical — check sysfs removable flag and bus path
    try:
        if int(open(f'/sys/block/{dev}/removable').read()) == 1: return True
    except: pass
    try:
        return 'usb' in os.readlink(f'/sys/block/{dev}')
    except: return False

def read_disk():
    global _prev_disk, _smart_cache
    now = time.time()
    disks = {}
    try:
        for l in open('/proc/diskstats'):
            p = l.split(); name = p[2]
            if not re.match(r'sd[a-z]$|nvme\d+n\d+$|vd[a-z]$|mmcblk\d+$|sr\d+$', name): continue
            disks[name] = (int(p[5]), int(p[9]), int(p[12]),
                           int(p[3]), int(p[7]), int(p[6]), int(p[10]), now)
    except: pass
    mounts = read_mounts()
    result = []
    for dev, (rd, wr, busy, rd_ios, wr_ios, rd_ms, wr_ms, ts) in sorted(disks.items()):
        prev = _prev_disk.get(dev)
        rd_s = wr_s = bp = riops = wiops = rd_lat = wr_lat = 0.0
        if prev:
            dt    = max(0.001, ts - prev[7])
            rd_s  = (rd - prev[0]) * 512 / dt
            wr_s  = (wr - prev[1]) * 512 / dt
            bp    = min(100, (busy - prev[2]) / (dt * 10))
            d_rd  = rd_ios - prev[3]; d_wr = wr_ios - prev[4]
            riops = d_rd / dt;        wiops = d_wr / dt
            rd_lat = (rd_ms - prev[5]) / d_rd if d_rd > 0 else 0.0
            wr_lat = (wr_ms - prev[6]) / d_wr if d_wr > 0 else 0.0
        _prev_disk[dev] = (rd, wr, busy, rd_ios, wr_ios, rd_ms, wr_ms, ts)
        sc = _smart_cache.get(dev, (0, 0))
        if now - sc[0] > SMART_TTL:
            temp = 0
            try:
                out = subprocess.check_output(['smartctl','-A',f'/dev/{dev}'],
                    timeout=3, stderr=subprocess.DEVNULL).decode()
                m = re.search(r'Temperature.*?(\d+)\s*$', out, re.M|re.I)
                if m: temp = int(m.group(1))
            except: pass
            _smart_cache[dev] = (now, temp)
        parts = [{'part': pn, **mounts[pn]} for pn in sorted(mounts) if _disk_parent(pn) == dev]
        result.append({'dev': dev, 'rd': rd_s, 'wr': wr_s, 'busy': bp,
                       'temp': _smart_cache.get(dev, (0,0))[1], 'parts': parts,
                       'riops': riops, 'wiops': wiops, 'rd_lat': rd_lat, 'wr_lat': wr_lat,
                       'rd_total': rd * 512, 'wr_total': wr * 512,
                       'size_b': _disk_size(dev),
                       'rotational': _disk_rotational(dev),
                       'scheduler': _disk_scheduler(dev),
                       'is_optical': dev.startswith('sr'),
                       'removable': _disk_is_removable(dev)})
    internal   = [d for d in result if not d['removable'] and not d['is_optical']]
    removable  = [d for d in result if d['removable'] or d['is_optical']]
    return internal, removable

# ── NET ────────────────────────────────────────────────────────────────────

def _get_ip(iface):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = struct.pack('16sH14s', iface.encode(), socket.AF_INET, b'\x00'*14)
        res = fcntl.ioctl(s.fileno(), 0x8915, ifreq)
        s.close()
        return socket.inet_ntoa(res[20:24])
    except:
        return ''

def _get_mask(iface):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = struct.pack('16sH14s', iface.encode(), socket.AF_INET, b'\x00'*14)
        res = fcntl.ioctl(s.fileno(), 0x891b, ifreq)
        s.close()
        mask = socket.inet_ntoa(res[20:24])
        bits = sum(bin(int(b)).count('1') for b in mask.split('.'))
        return str(bits)
    except:
        return ''

def _get_gw():
    global _gw_cache
    now = time.time()
    if now - _gw_cache[0] < 10.0: return _gw_cache[1]
    gw = ''
    try:
        for l in open('/proc/net/route'):
            f = l.split()
            if len(f) < 4: continue
            if f[1] == '00000000' and f[0] != 'Iface':
                raw = bytes.fromhex(f[2])
                gw = '.'.join(str(b) for b in reversed(raw))
                break
    except: pass
    _gw_cache = (now, gw)
    return gw

def _get_ping(gw):
    global _ping_cache
    now = time.time()
    cached = _ping_cache.get(gw)
    if cached and now - cached[0] < 5.0: return cached[1]
    ms = ''
    if gw:
        try:
            out = subprocess.check_output(
                ['ping', '-c1', '-W1', gw], timeout=2, stderr=subprocess.DEVNULL
            ).decode()
            m = re.search(r'time=(\S+)\s*ms', out)
            if m: ms = f"{float(m.group(1)):.0f}ms"
        except: pass
    _ping_cache[gw] = (now, ms)
    return ms

def _get_public_ip():
    global _pubip_cache, _pubip_proc, _pubip_srv_idx
    now = time.time()
    if _pubip_proc is not None:
        ret = _pubip_proc.poll()
        if ret is not None:
            try:
                out = _pubip_proc.stdout.read().decode().strip()
                out = out.strip().rstrip('.')
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', out):
                    _pubip_cache = (now, out)
            except: pass
            _pubip_proc = None
    ts, ip = _pubip_cache
    if ip and now - ts < 60.0: return ip
    if _pubip_proc is None:
        try:
            _PUBIP_URLS = [
                ['curl', '-sf', '--max-time', '4', 'https://checkip.amazonaws.com'],
                ['curl', '-sf', '--max-time', '4', 'https://api.ipify.org'],
                ['dig', '+short', 'myip.opendns.com', '@resolver1.opendns.com'],
            ]
            cmd = _PUBIP_URLS[_pubip_srv_idx % len(_PUBIP_URLS)]
            _pubip_srv_idx += 1
            _pubip_proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            )
            _pubip_cache = (now, ip)
        except: pass
    return ip

def _count_connections():
    global _conns_cache
    now = time.time()
    ts, data = _conns_cache
    if now - ts < 4.0: return data
    tcp = udp = ssh = vnc = unix = 0
    try:
        for l in open('/proc/net/tcp'):
            f = l.split()
            if len(f) < 4 or f[3] != '01': continue
            tcp += 1
            lport = int(f[1].split(':')[1], 16)
            if lport == 22:   ssh += 1
            if lport == 5900: vnc += 1
    except: pass
    try:
        for l in open('/proc/net/tcp6'):
            f = l.split()
            if len(f) < 4 or f[3] != '01': continue
            tcp += 1
            lport = int(f[1].split(':')[1], 16)
            if lport == 22:   ssh += 1
            if lport == 5900: vnc += 1
    except: pass
    try:
        for l in open('/proc/net/udp'):
            f = l.split()
            if len(f) < 4 or f[0] == 'sl': continue
            udp += 1
    except: pass
    try:
        for l in open('/proc/net/unix'):
            f = l.split()
            if len(f) < 1 or f[0] == 'Num': continue
            unix += 1
    except: pass
    data = {'tcp': tcp, 'udp': udp, 'ssh': ssh, 'vnc': vnc, 'unix': unix}
    _conns_cache = (now, data)
    return data

def _get_ssid(iface):
    global _wifi_cache
    now = time.time()
    cached = _wifi_cache.get(iface)
    if cached and now - cached[0] < 10.0: return cached[1]
    # run all methods in parallel — take highest-priority non-empty result
    attempts = [
        (['iw', 'dev', iface, 'link'],
         lambda out: next((l.split('SSID:', 1)[1].strip() for l in out.splitlines() if 'SSID:' in l), '')),
        (['iwgetid', '-r', iface],
         lambda out: out.strip()),
        (['iw', 'dev', iface, 'info'],
         lambda out: next((l.strip()[5:] for l in out.splitlines() if l.strip().startswith('ssid ')), '')),
        (['iwconfig', iface],
         lambda out: next((l.split('ESSID:"')[1].split('"')[0] for l in out.splitlines()
                           if 'ESSID:"' in l and 'off/any' not in l), '')),
        (['wpa_cli', '-i', iface, 'status'],
         lambda out: next((l.split('=',1)[1] for l in out.splitlines() if l.startswith('ssid=')), '')),
        (['wpa_cli', '-i', iface, '-p', '/var/run/wpa_supplicant', 'status'],
         lambda out: next((l.split('=',1)[1] for l in out.splitlines() if l.startswith('ssid=')), '')),
        (['nmcli', '-t', '-f', 'active,ssid', 'device', 'wifi'],
         lambda out: next((l.split(':',1)[1] for l in out.splitlines() if l.startswith('yes:')), '')),
    ]
    results = {}
    lock    = threading.Lock()
    def _try(i, cmd, parse):
        try:
            out = subprocess.check_output(cmd, timeout=1, stderr=subprocess.DEVNULL).decode()
            s   = parse(out)
            if s:
                with lock: results[i] = s
        except: pass
    threads = [threading.Thread(target=_try, args=(i, cmd, parse), daemon=True)
               for i, (cmd, parse) in enumerate(attempts)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=1.2)
    ssid = next((results[i] for i in range(len(attempts)) if i in results), '')
    _wifi_cache[iface] = (now, ssid)
    return ssid

def _get_signal(iface):
    try:
        for l in open('/proc/net/wireless'):
            if l.strip().startswith(iface + ':'):
                parts = l.split()
                return int(float(parts[3].rstrip('.')))
    except: pass
    return 0

def read_net():
    global _prev_net
    now = time.time()
    raw = {}
    try:
        for l in open('/proc/net/dev'):
            if ':' not in l: continue
            iface, rest = l.split(':', 1); iface = iface.strip()
            p = rest.split(); raw[iface] = (int(p[0]), int(p[8]), now)
    except: pass
    wifi_ifaces = set()
    try:
        for l in open('/proc/net/wireless'):
            if ':' in l:
                wifi_ifaces.add(l.split(':')[0].strip())
    except: pass
    nets = []
    for iface, (rx, tx, ts) in raw.items():
        if iface == 'lo': continue
        prev = _prev_net.get(iface); rx_s = tx_s = 0.0
        if prev:
            dt   = max(0.001, ts - prev[2])
            rx_s = (rx - prev[0]) / dt
            tx_s = (tx - prev[1]) / dt
        _prev_net[iface] = (rx, tx, ts)
        state_s = 'DOWN'
        try:
            state_s = open(f'/sys/class/net/{iface}/operstate').read().strip().upper()
        except: pass
        ip      = _get_ip(iface)
        mask    = _get_mask(iface) if ip else ''
        is_wifi = iface in wifi_ifaces
        ssid    = _get_ssid(iface) if is_wifi else ''
        signal  = _get_signal(iface) if is_wifi else 0
        mac     = ''
        try: mac = open(f'/sys/class/net/{iface}/address').read().strip()
        except: pass
        speed   = ''
        try:
            s = int(open(f'/sys/class/net/{iface}/speed').read())
            speed = f"{s}M" if s < 1000 else f"{s//1000}G"
        except: pass
        # IPv6 — read /proc/net/if_inet6 entry for this iface
        ipv6 = ''
        try:
            for l in open('/proc/net/if_inet6'):
                p = l.split()
                if len(p) >= 6 and p[5] == iface:
                    raw6 = p[0]
                    ipv6 = ':'.join(raw6[i:i+4] for i in range(0,32,4))
                    # compress leading zeros per group
                    ipv6 = re.sub(r'(?<![0-9a-f])(0{1,3})(?=[0-9a-f])', '', ipv6)
                    break
        except: pass
        nets.append({'iface': iface, 'rx': rx_s, 'tx': tx_s,
                     'state': state_s, 'ip': ip, 'mask': mask,
                     'ssid': ssid, 'signal': signal, 'is_wifi': is_wifi,
                     'mac': mac, 'speed': speed, 'ipv6': ipv6})
    bt_list = []
    try:
        bt_base = '/sys/class/bluetooth'
        for entry in sorted(os.listdir(bt_base)):
            try: bt_list.append(open(f'{bt_base}/{entry}/name').read().strip())
            except: bt_list.append(entry)
    except: pass
    return nets, bt_list

# ── BATTERY / UPTIME ───────────────────────────────────────────────────────

def read_battery():
    base = '/sys/class/power_supply'
    try: entries = os.listdir(base)
    except: return {}
    bat = {}
    for e in entries:
        p = f'{base}/{e}'
        try:
            typ = open(f'{p}/type').read().strip()
        except: continue
        if typ == 'Battery':
            try: bat['pct'] = int(open(f'{p}/capacity').read())
            except: pass
            try: bat['status'] = open(f'{p}/status').read().strip()
            except: pass
        elif typ == 'Mains':
            try: bat['ac'] = int(open(f'{p}/online').read()) == 1
            except: pass
    return bat

def read_uptime():
    try:
        secs = float(open('/proc/uptime').read().split()[0])
    except:
        return ''
    d = int(secs // 86400); secs %= 86400
    h = int(secs // 3600);  secs %= 3600
    m = int(secs // 60);    s = int(secs % 60)
    if d: return f"{d}d {h:02d}:{m:02d}:{s:02d}"
    return f"{h:02d}:{m:02d}:{s:02d}"

# ── VMs (tree view with RSS and uptime/exit code) ──────────────────────────

def _qemu_rss(pid):
    # Read VmRSS from /proc/PID/status — actual physical memory this QEMU process uses
    try:
        for l in open(f'/proc/{pid}/status', errors='replace'):
            if l.startswith('VmRSS:'):
                return int(l.split()[1])  # KB
    except: pass
    return 0

def _qemu_cpu_pct(pid):
    # rough: sum utime+stime from /proc/PID/stat — not delta, so just show raw ticks for now
    try:
        stat = open(f'/proc/{pid}/stat', errors='replace').read().split()
        return int(stat[13]) + int(stat[14])  # utime + stime ticks (not %)
    except: pass
    return 0

_vms_cache = (0.0, {})

def read_vms():
    global _vms_cache
    now = time.time()
    if now - _vms_cache[0] < 8.0: return _vms_cache[1]

    result = {'qemu': [], 'docker': [], 'podman': [],
              'vbox': [], 'vmware': [], 'proxmox_vms': [], 'proxmox_lxc': []}

    # KVM availability
    kvm_vendor = ''
    if   os.path.exists('/sys/module/kvm_intel'): kvm_vendor = 'intel'
    elif os.path.exists('/sys/module/kvm_amd'):   kvm_vendor = 'amd'
    result['kvm'] = {'avail': os.path.exists('/dev/kvm'), 'vendor': kvm_vendor}

    # scan /proc once for QEMU, VirtualBox, VMware
    try:
        for pid in os.listdir('/proc'):
            if not pid.isdigit(): continue
            try:
                comm  = open(f'/proc/{pid}/comm').read().strip()
                cmd   = open(f'/proc/{pid}/cmdline', errors='replace').read()
                parts = cmd.split('\x00')

                if 'qemu-system' in cmd:
                    name = f'vm{len(result["qemu"])+1}'
                    for i, arg in enumerate(parts):
                        if arg == '-name' and i+1 < len(parts):
                            name = parts[i+1].split(',')[0]; break
                    result['qemu'].append({'name': name, 'pid': pid, 'status': 'run',
                                           'rss_kb': _qemu_rss(pid)})

                elif comm in ('VBoxHeadless', 'VirtualBoxVM'):
                    name = ''
                    for i, p in enumerate(parts):
                        if p == '--startvm' and i+1 < len(parts):
                            name = parts[i+1]; break
                    result['vbox'].append({'name': name or f'vbox{pid}', 'pid': pid, 'status': 'run'})

                elif 'vmware-vmx' in comm:
                    vmx  = next((p for p in parts if p.endswith('.vmx')), '')
                    name = vmx.split('/')[-1].replace('.vmx','') if vmx else f'vmware{pid}'
                    result['vmware'].append({'name': name, 'pid': pid, 'status': 'run'})

            except: pass
    except: pass

    # docker / podman (subprocess, cached)
    for rt in ('docker', 'podman'):
        try:
            out = subprocess.check_output(
                [rt, 'ps', '-a', '--format', r'{{.Names}}\t{{.Status}}\t{{.RunningFor}}'],
                timeout=1, stderr=subprocess.DEVNULL).decode().strip()
            for line in out.splitlines():
                if '\t' not in line: continue
                p = line.split('\t')
                name, st_raw = p[0], p[1] if len(p)>1 else ''
                rf = p[2] if len(p)>2 else ''
                st = ('run'   if st_raw.startswith('Up')      else
                      'pause' if 'Paused'   in st_raw         else
                      'stop'  if st_raw.startswith('Exited')  else
                      'new'   if st_raw.startswith('Created') else st_raw[:6])
                ec = 0
                m = re.search(r'Exited \((\d+)\)', st_raw)
                if m: ec = int(m.group(1))
                result[rt].append({'name': name, 'status': st, 'running_for': rf, 'exit_code': ec})
        except: pass

    # Proxmox (qm list / pct list — only present on PVE host)
    try:
        out = subprocess.check_output(['qm','list'], timeout=2, stderr=subprocess.DEVNULL).decode()
        for l in out.splitlines()[1:]:
            p = l.split()
            if len(p) >= 3:
                result['proxmox_vms'].append({'id': p[0], 'name': p[1], 'status': p[2]})
    except: pass
    try:
        out = subprocess.check_output(['pct','list'], timeout=2, stderr=subprocess.DEVNULL).decode()
        for l in out.splitlines()[1:]:
            p = l.split()
            if len(p) >= 3:
                result['proxmox_lxc'].append({'id': p[0], 'status': p[1], 'name': p[2]})
    except: pass

    _vms_cache = (now, result)
    return result

# ── USB / AUDIO ────────────────────────────────────────────────────────────

def read_usb():
    devs = []
    try:
        base = '/sys/bus/usb/devices'
        for d in sorted(os.listdir(base)):
            prod_f = f'{base}/{d}/product'
            if not os.path.exists(prod_f): continue
            try:
                prod = open(prod_f).read().strip()
                if not prod: continue
                mfr = ''
                try: mfr = open(f'{base}/{d}/manufacturer').read().strip()
                except: pass
                label = f"{mfr} {prod}".strip() if mfr else prod
                if label not in [x['name'] for x in devs]:
                    devs.append({'name': label})
            except: pass
    except: pass
    return devs

def read_audio():
    devs = []
    try:
        for l in open('/proc/asound/cards'):
            m = re.match(r'\d+\s+\[\S+\s*\]:\s+(.+)', l.strip())
            if m: devs.append(m.group(1).strip())
    except: pass
    return devs

_audio_detail_cache = (0.0, {})

def _run(cmd, timeout=2):
    try:
        return subprocess.check_output(cmd, timeout=timeout,
                                       stderr=subprocess.DEVNULL).decode(errors='replace')
    except: return ''

def read_audio_detail():
    global _audio_detail_cache
    now = time.time()
    if now - _audio_detail_cache[0] < 8.0:
        return _audio_detail_cache[1]

    # scan /proc once for running daemon names
    procs = set()
    try:
        for pid in os.listdir('/proc'):
            if not pid.isdigit(): continue
            try: procs.add(open(f'/proc/{pid}/comm').read().strip())
            except: pass
    except: pass

    servers = {}  # key → info dict, in display order

    # ── ALSA ─────────────────────────────────────────────────────────────
    if os.path.exists('/proc/asound'):
        alsa = {'server': 'ALSA', 'active': True}
        streams = 0
        try:
            for card in os.listdir('/proc/asound'):
                cp = f'/proc/asound/{card}'
                if not os.path.isdir(cp): continue
                for pcm in os.listdir(cp):
                    pp = f'{cp}/{pcm}'
                    if not os.path.isdir(pp): continue
                    for sub in os.listdir(pp):
                        try:
                            if 'RUNNING' in open(f'{pp}/{sub}/status').read():
                                streams += 1
                        except: pass
        except: pass
        alsa['streams'] = streams
        hw = _read_alsa_hwparams()
        if hw: alsa.update(hw)
        servers['alsa'] = alsa

    # ── PipeWire ─────────────────────────────────────────────────────────
    pw_active = 'pipewire' in procs
    if pw_active or shutil.which('pw-dump'):
        pw = {'server': 'PipeWire', 'active': pw_active}
        try:
            import json as _json
            pw_raw = _run(['pw-dump'], timeout=3)
            if pw_raw:
                for node in _json.loads(pw_raw):
                    if 'Node' not in node.get('type', ''): continue
                    ni    = node.get('info', {})
                    if 'Audio/Sink' not in ni.get('props', {}).get('media.class', ''): continue
                    params   = ni.get('params', {})
                    pw_props = params.get('Props', [])
                    if pw_props:
                        p = pw_props[0]
                        ch_vols = p.get('channelVolumes', [])
                        pw['ch_vols'] = [round(min(v, 1.0) * 100) for v in ch_vols]
                        pw['ch_map']  = p.get('channelMap', [])
                        if ch_vols:
                            pw['vol'] = round(min(sum(ch_vols)/len(ch_vols), 1.0) * 100)
                        pw['muted'] = p.get('mute', False)
                    pw_fmt = params.get('Format', [])
                    if pw_fmt:
                        f0 = pw_fmt[0]
                        pw['fmt']  = f0.get('format', '')
                        pw['rate'] = f0.get('rate', 0)
                        pw['ch']   = f0.get('channels', 0)
                    break
        except: pass
        if 'vol' not in pw:
            wp = _run(['wpctl', 'get-volume', '@DEFAULT_AUDIO_SINK@'])
            if wp:
                m = re.search(r'Volume:\s*([\d.]+)', wp)
                if m: pw['vol'] = round(float(m.group(1)) * 100)
                pw['muted'] = '[MUTED]' in wp
        servers['pipewire'] = pw

    # ── WirePlumber ───────────────────────────────────────────────────────
    wp_active = 'wireplumber' in procs
    if wp_active or shutil.which('wpctl'):
        servers['wireplumber'] = {'server': 'WirePlumber', 'active': wp_active}

    # ── PulseAudio / pipewire-pulse ───────────────────────────────────────
    pa_active  = 'pulseaudio'     in procs
    ppw_active = 'pipewire-pulse' in procs
    if pa_active or ppw_active or shutil.which('pactl'):
        info = _run(['pactl', 'info'])
        if info:
            pa = {'active': pa_active or ppw_active}
            for l in info.splitlines():
                if   l.startswith('Server Name:'):    pa['server']    = l.split(':',1)[1].strip()
                elif l.startswith('Server Version:'): pa['version']   = l.split(':',1)[1].strip()
                elif l.startswith('Default Sink:'):   pa['sink_name'] = l.split(':',1)[1].strip()
                elif l.startswith('Default Source:'): pa['src_name']  = l.split(':',1)[1].strip()
            if 'server' not in pa:
                pa['server'] = 'pipewire-pulse' if ppw_active else 'PulseAudio'
            vout = _run(['pactl', 'get-sink-volume', '@DEFAULT_SINK@'])
            m = re.search(r'(\d+)%', vout)
            if m: pa['vol'] = int(m.group(1))
            pa['muted'] = 'yes' in _run(['pactl', 'get-sink-mute', '@DEFAULT_SINK@']).lower()
            sout = _run(['pactl', 'get-source-volume', '@DEFAULT_SOURCE@'])
            m = re.search(r'(\d+)%', sout)
            if m: pa['mic_vol'] = int(m.group(1))
            si = _run(['pactl', 'list', 'short', 'sink-inputs'])
            pa['streams']     = len([l for l in si.splitlines() if l.strip()])
            so = _run(['pactl', 'list', 'short', 'source-outputs'])
            pa['rec_streams'] = len([l for l in so.splitlines() if l.strip()])
            sinks_out = _run(['pactl', 'list', 'sinks', 'short'])
            pa['sinks'] = [l.split('\t')[1] for l in sinks_out.splitlines()
                           if l.strip() and '\t' in l]
            servers['pulse'] = pa

    # ── JACK ─────────────────────────────────────────────────────────────
    jack_active = any(p in procs for p in ('jackd', 'jackdbus', 'jackserver'))
    if jack_active or shutil.which('jack_lsp'):
        jk = {'server': 'JACK', 'active': jack_active}
        if jack_active:
            ports_out = _run(['jack_lsp'], timeout=1)
            if ports_out:
                jk['ports'] = len(ports_out.splitlines())
        servers['jack'] = jk

    _audio_detail_cache = (now, servers)
    return servers

def _read_alsa_hwparams():
    # read hw_params from first RUNNING PCM substream
    try:
        for card in sorted(os.listdir('/proc/asound')):
            cp = f'/proc/asound/{card}'
            if not os.path.isdir(cp): continue
            for pcm in sorted(os.listdir(cp)):
                pp = f'{cp}/{pcm}'
                if not os.path.isdir(pp): continue
                for sub in sorted(os.listdir(pp)):
                    sp = f'{pp}/{sub}'
                    try:
                        st = open(f'{sp}/status').read()
                        if 'RUNNING' not in st: continue
                    except: continue
                    try:
                        hw = {}
                        for l in open(f'{sp}/hw_params'):
                            k, _, v = l.partition(':')
                            k = k.strip(); v = v.strip()
                            if k == 'rate':      hw['rate'] = v.split()[0] + 'Hz'
                            elif k == 'format':  hw['fmt']  = v
                            elif k == 'channels':hw['ch']   = v
                            elif k == 'period_size': hw['period'] = v
                            elif k == 'buffer_size': hw['buf']    = v
                        return hw
                    except: pass
    except: pass
    return {}

def col_audio(aud, cards, h):
    # aud is now a dict of {key: server_info_dict}
    lines = []
    if not aud:
        lines.append(('no audio', C_WARN))
        for c in cards[:h-1]:
            lines.append((f"  {c}", C_DISK, curses.A_DIM))
        return lines

    for key, srv in aud.items():
        if len(lines) >= h: break
        name   = srv.get('server', key.upper())
        ver    = srv.get('version', '')
        active = srv.get('active', False)
        hdr    = f"{name}{' ' + ver if ver else ''}"
        lines.append((hdr, C_DISK if active else C_USB, 0 if active else curses.A_DIM))
        if not active:
            continue  # installed but not running — just dim header, no sub-rows

        if key == 'alsa':
            streams = srv.get('streams', 0)
            if len(lines) < h:
                lines.append((f"  streams: {streams}", C_DISK))
            hw_parts = []
            if srv.get('fmt'):  hw_parts.append(srv['fmt'])
            if srv.get('rate'): hw_parts.append(srv['rate'])
            if srv.get('ch'):   hw_parts.append(f"{srv['ch']}ch")
            if srv.get('period'): hw_parts.append(f"p:{srv['period']}")
            if hw_parts and len(lines) < h:
                lines.append((f"  {' '.join(str(x) for x in hw_parts)}", C_DISK))

        elif key == 'pipewire':
            vol   = srv.get('vol')
            muted = srv.get('muted', False)
            if vol is not None and len(lines) < h:
                mutes = ' [MUTE]' if muted else ''
                lines.append((f"  out: {vol:3d}%{mutes}", C_WARN if muted else _pct_color(vol)))
            ch_vols = srv.get('ch_vols', [])
            ch_map  = srv.get('ch_map', [])
            if ch_vols and len(lines) < h:
                ch_s = '  '.join(f"{(ch_map[i] if i < len(ch_map) else str(i))}:{ch_vols[i]}%"
                                 for i in range(len(ch_vols)))
                lines.append((f"  {ch_s}", C_DISK))
            fmt_parts = []
            if srv.get('fmt'):  fmt_parts.append(srv['fmt'])
            if srv.get('rate'): fmt_parts.append(f"{srv['rate']}Hz")
            if srv.get('ch'):   fmt_parts.append(f"{srv['ch']}ch")
            if fmt_parts and len(lines) < h:
                lines.append((f"  fmt: {' '.join(fmt_parts)}", C_DISK))

        elif key == 'wireplumber':
            pass  # header is enough; wpctl status too verbose

        elif key == 'pulse':
            vol   = srv.get('vol')
            muted = srv.get('muted', False)
            if vol is not None and len(lines) < h:
                mutes = ' [MUTE]' if muted else ''
                lines.append((f"  out: {vol:3d}%{mutes}", C_WARN if muted else _pct_color(vol)))
            mic = srv.get('mic_vol')
            if mic is not None and len(lines) < h:
                lines.append((f"  mic: {mic:3d}%", _pct_color(mic) if mic > 80 else C_DISK))
            if len(lines) < h:
                lines.append((f"  play:{srv.get('streams',0)}  rec:{srv.get('rec_streams',0)}", C_DISK))
            sink = srv.get('sink_name', '')
            if sink and len(lines) < h:
                lines.append((f"  sink: {sink}", C_DISK))
            for s in srv.get('sinks', [])[:max(0, h - len(lines))]:
                lines.append((f"   >{s}", C_DISK))

        elif key == 'jack':
            if 'ports' in srv and len(lines) < h:
                lines.append((f"  ports: {srv['ports']}", C_DISK))

    for c in cards[:max(0, h - len(lines))]:
        lines.append((f"card: {c}", C_DISK))
    return lines

# ── HOOKS ──────────────────────────────────────────────────────────────────

def read_hooks():
    global _hook_cache
    hooks_dir = os.path.expanduser('~/.config/bsc/hooks')
    if not os.path.isdir(hooks_dir): return {}
    now = time.time()
    result = {}
    try:
        for fname in sorted(os.listdir(hooks_dir)):
            fpath = os.path.join(hooks_dir, fname)
            if not os.access(fpath, os.X_OK): continue
            cached = _hook_cache.get(fpath)
            if cached and now - cached[0] < HOOK_TTL:
                result[fname] = cached[1]; continue
            lines = []
            try:
                out = subprocess.check_output(fpath, timeout=3, stderr=subprocess.DEVNULL)
                lines = out.decode(errors='replace').splitlines()
            except: pass
            _hook_cache[fpath] = (now, lines)
            result[fname] = lines
    except: pass
    return result

# ── PROCS ──────────────────────────────────────────────────────────────────

_proc_counts_cache = (0.0, {})

def read_proc_counts():
    global _proc_counts_cache
    now = time.time()
    ts, data = _proc_counts_cache
    if now - ts < 2.0: return data
    counts = {'R': 0, 'S': 0, 'D': 0, 'Z': 0, 'T': 0}
    try:
        for pid in os.listdir('/proc'):
            if not pid.isdigit(): continue
            try:
                state = open(f'/proc/{pid}/stat', errors='replace').read().split()[2]
                if state in counts: counts[state] += 1
            except: pass
    except: pass
    _proc_counts_cache = (now, counts)
    return counts

def read_procs(sort_by='cpu', filt='user', search=''):
    global _prev_proc
    now = time.time()
    HZ  = os.sysconf('SC_CLK_TCK')
    procs = []
    try:
        pids = [d for d in os.listdir('/proc') if d.isdigit()]
    except: return []
    for pid in pids:
        try:
            stat = open(f'/proc/{pid}/stat', errors='replace').read()
            m = re.match(r'\d+ \((.+)\) \S .+? \d+ \d+ \d+ \d+ \d+ \d+ \d+ (\d+) \d+ (\d+)', stat)
            if not m: continue
            name  = m.group(1)
            ticks = int(m.group(2)) + int(m.group(3))
            prev  = _prev_proc.get(pid); cpu_pct = 0.0
            if prev:
                dt = max(0.001, now - prev[1]); cpu_pct = 100*(ticks-prev[0])/(dt*HZ)
            _prev_proc[pid] = (ticks, now)
            uid = 0; mem_kb = 0
            try:
                for l in open(f'/proc/{pid}/status', errors='replace'):
                    if   l.startswith('Uid:'):   uid    = int(l.split()[1])
                    elif l.startswith('VmRSS:'): mem_kb = int(l.split()[1])
            except: pass
            cmd = ''
            try: cmd = open(f'/proc/{pid}/cmdline', errors='replace').read().replace('\0',' ').strip()
            except: pass
            is_kern = bool(KERN_RE.match(name)) or (not cmd and uid == 0 and name[0].islower())
            tc = 'k' if is_kern else ('r' if uid == 0 else 'u')
            if filt == 'user' and (uid == 0 or is_kern): continue
            if filt == 'root' and (uid != 0 or is_kern): continue
            if filt == 'kern' and not is_kern:            continue
            if search and search.lower() not in (cmd or name).lower(): continue
            procs.append({'pid': pid, 'name': name, 'cmd': cmd or name,
                          'cpu': cpu_pct, 'mem_kb': mem_kb, 'uid': uid, 'tc': tc})
        except: continue
    procs.sort(key=lambda p: p['cpu' if sort_by == 'cpu' else 'mem_kb'], reverse=True)
    return procs

def read_proc_desc(pid):
    status = {}
    try:
        for l in open(f'/proc/{pid}/status', errors='replace'):
            for k in ('Pid','Uid','State','Threads','VmRSS','Name'):
                if l.startswith(k + ':'): status[k] = l.split(':',1)[1].strip()
    except: pass
    cmdline = ''
    try:
        cmdline = open(f'/proc/{pid}/cmdline', errors='replace').read().replace('\0', ' ').strip()
    except: pass
    nice = ''
    try:
        stat = open(f'/proc/{pid}/stat', errors='replace').read()
        parts = stat.split()
        if len(parts) > 18: nice = parts[18]
    except: pass
    vmrss_kb = 0
    try: vmrss_kb = int(status.get('VmRSS', '0 kB').split()[0])
    except: pass
    l1 = (f"PID={status.get('Pid','?')} UID={status.get('Uid','?').split()[0]} "
          f"STATE={status.get('State','?').split()[0]} "
          f"THREADS={status.get('Threads','?')} "
          f"NICE={nice} VmRSS={fmt_mem(vmrss_kb)}")
    l2 = f"CMD: {cmdline or '?'}"
    return l1, l2

# ── STRACE-LIKE: poll /proc/PID/syscall each refresh ──────────────────────

# syscall number → name table (x86_64 subset, most common ones)
_SYSCALL_NAMES = {
    0:'read', 1:'write', 2:'open', 3:'close', 4:'stat', 5:'fstat', 6:'lstat',
    7:'poll', 8:'lseek', 9:'mmap', 10:'mprotect', 11:'munmap', 12:'brk',
    13:'rt_sigaction', 14:'rt_sigprocmask', 17:'pread64', 18:'pwrite64',
    19:'readv', 20:'writev', 21:'access', 22:'pipe', 23:'select', 24:'sched_yield',
    28:'madvise', 32:'dup', 33:'dup2', 35:'nanosleep', 38:'setitimer',
    39:'getpid', 41:'socket', 42:'connect', 43:'accept', 44:'sendto',
    45:'recvfrom', 46:'sendmsg', 47:'recvmsg', 49:'bind', 50:'listen',
    51:'getsockname', 52:'getpeername', 54:'setsockopt', 55:'getsockopt',
    56:'clone', 57:'fork', 58:'vfork', 59:'execve', 60:'exit', 61:'wait4',
    62:'kill', 63:'uname', 72:'fcntl', 73:'flock', 74:'fsync', 75:'fdatasync',
    76:'truncate', 77:'ftruncate', 78:'getdents', 79:'getcwd', 80:'chdir',
    82:'rename', 83:'mkdir', 85:'creat', 87:'unlink', 89:'readlink',
    96:'gettimeofday', 97:'getrlimit', 98:'getrusage', 99:'sysinfo',
    102:'getuid', 104:'getgid', 105:'setuid', 106:'setgid', 107:'geteuid',
    108:'getegid', 111:'getpgrp', 131:'sigaltstack', 158:'arch_prctl',
    186:'gettid', 202:'futex', 203:'sched_setaffinity', 204:'sched_getaffinity',
    218:'set_tid_address', 228:'clock_gettime', 231:'exit_group',
    232:'epoll_wait', 233:'epoll_ctl', 257:'openat', 262:'newfstatat',
    265:'linkat', 280:'utimensat', 281:'epoll_pwait', 290:'eventfd2',
    291:'epoll_create1', 292:'dup3', 293:'pipe2', 318:'getrandom',
    332:'statx', 334:'io_uring_setup', 335:'io_uring_enter',
}

def _rle_append(ring, entry):
    # run-length encode: if last entry is same syscall+pid, bump ×N counter
    if ring and ring[-1].startswith(entry):
        last = ring[-1]
        if ' ×' in last:
            base, _, cnt = last.rpartition(' ×')
            try: ring[-1] = f"{base} ×{int(cnt)+1}"; return
            except: pass
        else:
            ring[-1] = last + ' ×2'; return
    ring.append(entry)

def _ensure_perf(core):
    # perf trace --cpu N: per-core event-driven, needs perf + paranoid<=2
    global _perf_proc, _perf_core_active, _perf_buf
    if _perf_proc and _perf_core_active == core and _perf_proc.poll() is None:
        return _perf_proc
    if _perf_proc:
        try: _perf_proc.kill()
        except: pass
        _perf_proc = None; _perf_buf = b''
    if not shutil.which('perf'):
        return None
    try:
        _perf_proc = subprocess.Popen(
            ['perf', 'trace', '--cpu', str(core), '--no-pager', '-q'],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        fl = fcntl.fcntl(_perf_proc.stderr.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(_perf_proc.stderr.fileno(), fcntl.F_SETFL, fl | os.O_NONBLOCK)
        _perf_core_active = core
        return _perf_proc
    except:
        _perf_proc = None; return None

def _core_sampler_loop():
    # Level 1: bpftrace system-wide (eBPF) — routes cpu\tpid\tcomm\tnr to per-core rings
    # Level 2: perf trace --cpu N for the watched core + /proc for others
    # Level 3: /proc/PID/stat field 39 scan — populates ALL core rings in one pass
    global _core_sampler_run, _perf_buf
    bpf_buf = b''
    while _core_sampler_run:
        core = _core_watch

        bpf = _ensure_bpf()
        if bpf and bpf.poll() is None:
            try:
                ready = select.select([bpf.stdout], [], [], 0.05)
                if ready[0]:
                    bpf_buf += bpf.stdout.read(16384)
                while b'\n' in bpf_buf:
                    line, bpf_buf = bpf_buf.split(b'\n', 1)
                    parts = line.decode(errors='replace').split('\t')
                    if len(parts) >= 4:
                        try:   cn = int(parts[0].strip())
                        except: continue
                        pid  = parts[1].strip()
                        comm = parts[2].strip()
                        try:   nr = int(parts[3].strip())
                        except: nr = -1
                        r = _core_rings.setdefault(cn, collections.deque(maxlen=1000))
                        _rle_append(r, f"{pid}:{comm[:12]}  {_SYSCALL_NAMES.get(nr, f'sys_{nr}')}")
            except (BlockingIOError, OSError): pass
            continue

        # perf trace for watched core, /proc for all others
        perf = _ensure_perf(core)
        if perf and perf.poll() is None:
            ring = _core_rings.setdefault(core, collections.deque(maxlen=1000))
            try:
                ready = select.select([perf.stderr], [], [], 0.02)
                if ready[0]:
                    _perf_buf += perf.stderr.read(8192)
                while b'\n' in _perf_buf:
                    line, _perf_buf = _perf_buf.split(b'\n', 1)
                    s = line.decode(errors='replace').strip()
                    m = re.match(r'[\d.]+\s+(\S+)/(\d+)\s+(\w+)\(', s)
                    if m:
                        _rle_append(ring, f"{m.group(2)}:{m.group(1)[:12]}  {m.group(3)}")
            except (BlockingIOError, OSError): pass

        # /proc: scan ALL PIDs, populate every core's ring in one pass
        try:
            for pid in os.listdir('/proc'):
                if not pid.isdigit(): continue
                try:
                    stat = open(f'/proc/{pid}/stat').read()
                    i = stat.rfind(')')
                    fields = stat[i+2:].split()
                    if len(fields) <= 36: continue
                    cn   = int(fields[36])
                    comm = stat[stat.index('(')+1:i]
                    sc_raw = open(f'/proc/{pid}/syscall', errors='replace').read().strip()
                    if not sc_raw: continue
                    if sc_raw == 'running':
                        sc_s = '[userspace]'
                    else:
                        p    = sc_raw.split()
                        try: nr = int(p[0])
                        except: nr = -1
                        sc_s = f"{_SYSCALL_NAMES.get(nr, f'sys_{nr}')}({' '.join(p[1:5])})"
                    r = _core_rings.setdefault(cn, collections.deque(maxlen=1000))
                    _rle_append(r, f"{pid}:{comm[:12]}  {sc_s}")
                except: pass
        except: pass
        time.sleep(0.01)

def _core_sampler_start():
    global _core_sampler_thread, _core_sampler_run
    if _core_sampler_thread and _core_sampler_thread.is_alive():
        return
    _core_sampler_run = True
    _core_sampler_thread = threading.Thread(target=_core_sampler_loop, daemon=True)
    _core_sampler_thread.start()


def _disasm(pid, rip, n_insn=16):
    # read bytes at rip from /proc/PID/mem, disassemble with ndisasm or objdump
    # returns list of strings ready for display
    try:
        fd = os.open(f'/proc/{pid}/mem', os.O_RDONLY)
        bs = os.pread(fd, 96, rip)   # 96 bytes ~ 16 insn average
        os.close(fd)
    except:
        return ['  (cannot read /proc/PID/mem — need root)']
    if not bs:
        return ['  (no data at rip)']

    if shutil.which('ndisasm'):
        # ndisasm -b 64 -o ORIGIN - reads raw binary from stdin
        try:
            r = subprocess.run(
                ['ndisasm', '-b', '64', f'-o0x{rip:016x}', '-'],
                input=bs, capture_output=True, timeout=0.5
            )
            out = r.stdout.decode(errors='replace').splitlines()
            return out[:n_insn] if out else ['  (ndisasm: no output)']
        except: pass

    if shutil.which('objdump'):
        # write 96 raw bytes to /tmp/bsc_asm.bin — ephemeral, always overwritten
        try:
            with open('/tmp/bsc_asm.bin', 'wb') as f: f.write(bs)
            r = subprocess.run(
                ['objdump', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
                 '-D', f'--adjust-vma=0x{rip:016x}', '/tmp/bsc_asm.bin'],
                capture_output=True, timeout=0.5
            )
            lines = []
            for l in r.stdout.decode(errors='replace').splitlines():
                # instruction lines: "    7fff...:   48 89 e5    mov rbp,rsp"
                ls = l.strip()
                if not ls or ls.endswith(':'): continue
                if ':' in ls and ls[0] not in 'D/':
                    lines.append('  ' + ls)
            return lines[:n_insn] if lines else ['  (objdump: no output)']
        except: pass

    # raw fallback — hex bytes grouped in 4-byte chunks
    lines = []
    for i in range(0, min(len(bs), 48), 8):
        chunk = bs[i:i+8]
        hex_s = ' '.join(f'{b:02x}' for b in chunk)
        lines.append(f"  {rip+i:#018x}  {hex_s}")
    return lines

# ── DEV global data ────────────────────────────────────────────────────────

def read_dev_global():
    d = {}
    try:
        for l in open('/proc/vmstat'):
            k, v = l.split()
            d[k] = int(v)
    except: pass
    mi = {}
    try:
        for l in open('/proc/meminfo'):
            k, v = l.split(':'); mi[k.strip()] = int(v.split()[0])
    except: pass
    d['mi'] = mi
    try:
        sc = open('/proc/schedstat').readlines()
        total_sw = sum(int(l.split()[9]) for l in sc
                       if l.startswith('cpu') and not l.startswith('cpu ')
                       and len(l.split()) > 9)
        d['nr_switches'] = total_sw
    except: d['nr_switches'] = 0
    freqs = []
    try:
        for cpu in sorted(os.listdir('/sys/devices/system/cpu')):
            m = re.match(r'cpu(\d+)$', cpu)
            if not m: continue
            try:
                freqs.append(int(open(
                    f'/sys/devices/system/cpu/{cpu}/cpufreq/scaling_cur_freq').read())//1000)
            except: pass
    except: pass
    d['freqs'] = freqs
    d['gov'] = ''
    try:
        d['gov'] = open('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor').read().strip()
    except: pass
    try:
        d['hugepages_free']  = int(open('/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages').read())
        d['hugepages_total'] = int(open('/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages').read())
    except:
        d['hugepages_free'] = d['hugepages_total'] = 0
    d['dirty']     = mi.get('Dirty', 0)
    d['writeback'] = mi.get('Writeback', 0)
    d['cached']    = mi.get('Cached', 0)
    return d

def read_socket_stats():
    global _sock_cache
    now = time.time()
    ts, data = _sock_cache if '_sock_cache' in dir() else (0.0, {})
    # use module-level var
    try: ts, data = globals().get('_sock_cache_g', (0.0, {}))
    except: pass
    if now - ts < 2.0 and data: return data
    TCP_ST = {'01':'ESTAB','02':'SYN_SN','03':'SYN_RV','04':'FIN_W1',
              '05':'FIN_W2','06':'TW','07':'CLOSE','08':'CL_WT',
              '09':'LAST_AK','0A':'LISTEN','0B':'CLOSING'}
    tcp = {}
    for f in ('/proc/net/tcp', '/proc/net/tcp6'):
        try:
            for l in open(f):
                p = l.split()
                if len(p) < 4 or p[0] == 'sl': continue
                name = TCP_ST.get(p[3].upper(), p[3])
                tcp[name] = tcp.get(name, 0) + 1
        except: pass
    udp = 0
    for f in ('/proc/net/udp', '/proc/net/udp6'):
        try: udp += max(0, len(open(f).readlines()) - 1)
        except: pass
    unix = 0
    try: unix = max(0, len(open('/proc/net/unix').readlines()) - 1)
    except: pass
    data = {'tcp': tcp, 'udp': udp, 'unix': unix}
    globals()['_sock_cache_g'] = (now, data)
    return data

_fw_cache   = (0.0, [])
_sb_cache   = (0.0, [])

def _firewall_status():
    global _fw_cache
    now = time.time()
    if now - _fw_cache[0] < 10.0: return _fw_cache[1]
    fw = []
    try:
        chains = open('/proc/net/ip_tables_names').read().strip()
        if chains: fw.append(f"ipt:{chains.replace(chr(10),',')}")
    except: pass
    try:
        if os.path.exists('/proc/net/nf_tables'): fw.append('nft')
    except: pass
    try:
        for l in open('/etc/ufw/ufw.conf'):
            if l.strip() == 'ENABLED=yes': fw.append('ufw'); break
    except: pass
    if os.path.exists('/run/firewalld/firewalld.pid'): fw.append('firewalld')
    result = fw if fw else ['none']
    _fw_cache = (now, result)
    return result

def _sandbox_status():
    global _sb_cache
    now = time.time()
    if now - _sb_cache[0] < 10.0: return _sb_cache[1]
    s = []
    try:
        n = len(open('/sys/kernel/security/apparmor/profiles').readlines())
        if n > 0: s.append(f"aa:{n}")
    except: pass
    try:
        e = open('/sys/fs/selinux/enforce').read().strip()
        s.append(f"sel:{'enf' if e=='1' else 'prm'}")
    except: pass
    try:
        for l in open('/proc/self/status'):
            if l.startswith('Seccomp:'):
                v = l.split()[1]
                if v != '0': s.append(f"seccomp:{v}")
                break
    except: pass
    result = s if s else ['none']
    _sb_cache = (now, result)
    return result

# ── column builders ────────────────────────────────────────────────────────

def _pct_color(pct):
    if pct >= 80: return C_WARN
    if pct >= 40: return C_RAM
    return C_DISK

def col_cpu(cores, load, rapl_w, h):
    lines = []
    max_c = h - 1
    for i, c in enumerate(cores[:max_c]):
        p = c['pct']
        freq_s = f"{c['freq']}MHz" if c['freq'] else "--MHz"
        temp_s = f"{c['temp']:2d}°" if c['temp'] else "--°"
        lines.append((f"{i:2d} {p:3.0f}% | {freq_s} | {temp_s}", _pct_color(p)))
    avg_pct = sum(c['pct'] for c in cores) / len(cores) if cores else 0
    lines.append((f"ld:{load[0]:.1f}/{load[1]:.1f}/{load[2]:.1f} {rapl_w:.0f}W", _pct_color(avg_pct)))
    if len(lines) < h and cores:
        turbo_n = sum(1 for c in cores if c.get('is_turbo'))
        thr_max = max((c.get('throttle', 0) for c in cores), default=0)
        lines.append((f"turbo:{turbo_n}/{len(cores)} thr:{thr_max}", C_DISK))
    return lines

def col_ram_gpu(mem, gpu, h):
    # RAM rows — missing entries in red, not dim
    def mrow(lbl, used, tot, cp, missing=False):
        if missing:
            return (f"{lbl} {'--':>6}/{'--':<6} ---", C_WARN)
        p = pct2(used, tot)
        return (f"{lbl} {fmt_mem(used):>6}/{fmt_mem(tot):<6} {p:3d}%", cp)
    lines = []
    ru = mem.get('used',0); rt = mem.get('total',1)
    lines.append(mrow('RAM', ru, rt, _pct_color(pct2(ru, rt))))
    su = mem.get('swap_used',0); st = mem.get('swap_tot',1)
    lines.append(mrow('SWP', su, st, _pct_color(pct2(su, st)),
                       missing=(mem.get('swap_tot',0) == 0)))
    zu = mem.get('zram_used',0); zt = mem.get('zram_tot',1)
    lines.append(mrow('ZRM', zu, zt, _pct_color(pct2(zu, zt)),
                       missing=(mem.get('zram_tot',0) == 0)))
    # GPU — no separator title, just data below RAM
    source = gpu.get('source', '')
    model  = gpu.get('model', 'GPU')
    drv    = gpu.get('driver', '')
    if not drv:
        try: drv = open('/sys/module/nvidia/version').read().strip()
        except: pass
    if source in ('smi', 'nvml'):
        mp    = pct2(gpu.get('mem_used',0), gpu.get('mem_tot',1))
        fan_s = f" fan:{gpu['fan']}%" if gpu.get('fan', -1) >= 0 else ''
        lines.append((f"{model[:24]}", C_GPU))
        lines.append((f"util:{gpu['util']:3d}% {gpu['temp']:2d}C {gpu['power']:.0f}W{fan_s}", C_GPU))
        lines.append((f"VRAM {fmt_mem(gpu.get('mem_used',0)*1024)}/{fmt_mem(gpu.get('mem_tot',0)*1024)} {mp}%", C_GPU))
        if drv: lines.append((f"drv:{drv}", C_GPU))
    elif source in ('hwmon', 'rocm'):
        lines.append((f"{model[:24]}", C_GPU))
        parts = []
        if 'util'  in gpu: parts.append(f"util:{gpu['util']}%")
        if 'temp'  in gpu: parts.append(f"{gpu['temp']:2d}C")
        if 'power' in gpu: parts.append(f"{gpu['power']:.0f}W")
        if parts: lines.append((' '.join(parts), C_GPU))
        if 'mem_used' in gpu:
            mp = pct2(gpu['mem_used'], gpu.get('mem_tot',1))
            lines.append((f"VRAM {fmt_mem(gpu['mem_used']*1024)}/{fmt_mem(gpu.get('mem_tot',0)*1024)} {mp}%", C_GPU))
        if drv: lines.append((f"drv:{drv}", C_GPU))
    elif source == 'nvidia-proc':
        lines.append((f"{model[:24]}", C_GPU))
        temp_s = f"{gpu['temp']:2d}C" if 'temp' in gpu else "--C"
        lines.append((f"drv:{drv or '?'} {temp_s}", C_GPU))
        lines.append(('install nvidia-smi', C_GPU, curses.A_DIM))
    else:
        lines.append(('GPU: not detected', C_GPU, curses.A_DIM))
    return lines

def _disk_model(dev):
    try: return open(f'/sys/block/{dev}/device/model').read().strip()[:20]
    except: return ''

def _disk_size(dev):
    try: return int(open(f'/sys/block/{dev}/size').read()) * 512
    except: return 0

def _disk_rotational(dev):
    # 0=SSD/NVMe, 1=HDD, None=unknown
    try: return int(open(f'/sys/block/{dev}/queue/rotational').read()) == 1
    except: return None

def _disk_scheduler(dev):
    try:
        s = open(f'/sys/block/{dev}/queue/scheduler').read()
        m = re.search(r'\[(\S+)\]', s)
        return m.group(1) if m else s.strip().split()[0][:12]
    except: return ''

def col_disk(disks, h):
    lines = []
    for di, d in enumerate(disks):
        if len(lines) >= h: break
        dev  = d['dev']
        rot  = d.get('rotational')
        kind = 'HDD' if rot else ('SSD' if rot is not None else '???')
        sz_b   = d.get('size_b', 0)
        sz_s   = fb(sz_b) if sz_b else '?'
        model  = _disk_model(dev)
        sched  = _disk_scheduler(dev)
        if len(lines) >= h: break
        hdr    = f"{dev}  {kind} {sz_s}"
        if model: hdr += f"  {model[:16]}"
        if sched: hdr += f"  [{sched}]"
        lines.append((hdr, C_DISK))
        idle   = d['rd'] < 1024 and d['wr'] < 1024 and d['busy'] < 1.0
        attr   = curses.A_DIM if idle else 0
        temp_s = f"{d['temp']:2d}C" if d['temp'] else "--C"
        if len(lines) < h:
            lines.append((
                f"  i{fb(d['rd']):>5}/s o{fb(d['wr']):>5}/s  busy:{d['busy']:2.0f}%  {temp_s}",
                C_DISK, attr))
        if len(lines) < h:
            lines.append((
                f"  R:{d.get('riops',0):4.0f} W:{d.get('wiops',0):4.0f} iops"
                f"  Rl:{d.get('rd_lat',0):.1f} Wl:{d.get('wr_lat',0):.1f}ms",
                C_DISK, attr))
        if len(lines) < h:
            rd_tot = d.get('rd_total', 0); wr_tot = d.get('wr_total', 0)
            lines.append((
                f"  total: i{fb(rd_tot)} o{fb(wr_tot)} since boot",
                C_DISK, curses.A_DIM))
        for i, part in enumerate(d.get('parts', [])):
            if len(lines) >= h: break
            pct  = pct2(part['used'], part['total'])
            clr  = _pct_color(pct)
            tree = '└' if i == len(d['parts'])-1 else '├'
            mp   = part['mp']
            if len(mp) > 10:
                mp_parts = mp.strip('/').split('/')
                mp = '/' + '/'.join(mp_parts[-2:]) if len(mp_parts) >= 2 else '/' + mp_parts[-1]
            fs_t = part.get('fs','?')[:8]
            lines.append((
                f" {tree}{part['part']:<8}{mp:<9}{fs_t:<8}"
                f"{fmt_mem(part['used']//1024):>5}/{fmt_mem(part['total']//1024):<5} {pct:3d}%",
                clr))
        # blank separator between disks (not after last)
        if di < len(disks) - 1 and len(lines) < h:
            lines.append(('', C_USB))
    return lines

def col_cpu_ram_gpu(cores, load, rapl_w, mem, gpu, h):
    lines = []
    avg_pct = sum(c['pct'] for c in cores) / len(cores) if cores else 0
    try: gov = open('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor').read().strip()
    except: gov = '?'
    # aggregate CPU — split to 2 lines: load on line 1, power+governor on line 2
    lines.append((f"CPU {avg_pct:3.0f}%  ld:{load[0]:.1f}/{load[1]:.1f}/{load[2]:.1f}",
                  _pct_color(avg_pct)))
    if len(lines) < h:
        lines.append((f"  {rapl_w:.0f}W  {gov}", _pct_color(avg_pct)))
    # per-core
    for i, c in enumerate(cores):
        if len(lines) >= h: break
        freq_s = f"{c['freq']}MHz" if c['freq'] else "--MHz"
        temp_s = f"{c['temp']:2d}°" if c['temp'] else "--°"
        lines.append((f"{i:2d} {c['pct']:3.0f}% | {freq_s} | {temp_s}", _pct_color(c['pct'])))
    if len(lines) < h and cores:
        turbo_n = sum(1 for c in cores if c.get('is_turbo'))
        thr_max = max((c.get('throttle', 0) for c in cores), default=0)
        lines.append((f"turbo:{turbo_n}/{len(cores)} thr:{thr_max}", C_DISK))
    # RAM
    def mrow(lbl, used, tot, cp, missing=False):
        if missing: return (f"{lbl} --/-- ---", C_WARN)
        p = pct2(used, tot)
        return (f"{lbl} {fmt_mem(used):>6}/{fmt_mem(tot):<6} {p:3d}%", cp)
    if len(lines) < h:
        ru = mem.get('used',0); rt = mem.get('total',1)
        lines.append(mrow('RAM', ru, rt, _pct_color(pct2(ru, rt))))
    if len(lines) < h:
        su = mem.get('swap_used',0); st = mem.get('swap_tot',1)
        lines.append(mrow('SWP', su, st, _pct_color(pct2(su, st)), missing=(mem.get('swap_tot',0)==0)))
    if len(lines) < h:
        zu = mem.get('zram_used',0); zt = mem.get('zram_tot',1)
        if mem.get('zram_tot',0) > 0:
            lines.append(mrow('ZRM', zu, zt, _pct_color(pct2(zu, zt))))
    # GPU
    source = gpu.get('source', '')
    model  = gpu.get('model', 'GPU')
    drv    = gpu.get('driver', '')
    if not drv:
        try: drv = open('/sys/module/nvidia/version').read().strip()
        except: pass
    if len(lines) < h and source in ('smi', 'nvml'):
        mp = pct2(gpu.get('mem_used',0), gpu.get('mem_tot',1))
        fan_s = f" fan:{gpu['fan']}%" if gpu.get('fan', -1) >= 0 else ''
        lines.append((f"{model[:24]}", C_GPU))
        if len(lines) < h:
            lines.append((f"util:{gpu['util']:3d}% {gpu['temp']:2d}C {gpu['power']:.0f}W{fan_s}", C_GPU))
        if len(lines) < h:
            lines.append((f"VRAM {fmt_mem(gpu.get('mem_used',0)*1024)}/{fmt_mem(gpu.get('mem_tot',0)*1024)} {mp}%", C_GPU))
        if drv and len(lines) < h:
            lines.append((f"drv:{drv}", C_GPU))
    elif len(lines) < h and source in ('hwmon', 'rocm'):
        lines.append((f"GPU temp:{gpu.get('temp',0)}C", C_GPU))
    elif len(lines) < h:
        lines.append(('GPU: no data', C_WARN))
    return lines

def col_net(nets, bt, h, scroll=0):
    gw    = _get_gw()
    ping  = _get_ping(gw) if gw else ''
    pubip = _get_public_ip()
    conns = _count_connections()
    lines = []
    # hostname + public IP
    try:    hn = open('/etc/hostname').read().strip()
    except: hn = ''
    lines.append((f"host:{hn}  gw:{gw or '--'}  pub:{pubip or '...'}", C_DISK))
    # ping + connection counts on one line
    conn_s = f"ping:{ping or '--'}  tcp:{conns.get('tcp',0)} udp:{conns.get('udp',0)} unix:{conns.get('unix',0)}"
    for k in ('ssh','vnc'):
        if conns.get(k,0): conn_s += f"  {k}:{conns[k]}"
    lines.append((conn_s, C_DISK))
    # DNS servers
    dns = []
    try:
        for l in open('/etc/resolv.conf'):
            if l.startswith('nameserver'):
                dns.append(l.split()[1])
    except: pass
    if dns and len(lines) < h:
        lines.append((f"dns: {' '.join(dns[:3])}", C_DISK))
    # VPN detection
    vpn_ifaces = [n for n in nets if any(n['iface'].startswith(p) for p in ('tun','tap','wg','vpn','ppp')) and n['state']=='UP']
    if vpn_ifaces and len(lines) < h:
        vpn_s = ' '.join(f"{v['iface']}({v['ip'] or '?'})" for v in vpn_ifaces[:3])
        lines.append((f"VPN: {vpn_s}", C_GPU))
    # per-interface (scrollable with i/o)
    visible = nets[scroll:]
    for n in visible:
        if len(lines) >= h: break
        is_vpn  = any(n['iface'].startswith(p) for p in ('tun','tap','wg','vpn','ppp'))
        is_down = n['state'] != 'UP'
        attr    = curses.A_DIM if is_down else 0
        ip_mask = f"{n['ip']}/{n['mask']}" if n['ip'] and n['mask'] else (n['ip'] or '--')
        spd     = f" {n['speed']}" if n.get('speed') else ''
        itype   = 'WiFi' if n['is_wifi'] else ('VPN' if is_vpn else 'LAN ')
        lines.append((f"{n['iface']:<12} {itype}  {n['state']:<4}{spd}  {ip_mask}", C_NET, attr))
        if n.get('mac') and len(lines) < h:
            lines.append((f"  mac:{n['mac']}", C_USB, curses.A_DIM))
        if n.get('ipv6') and not is_down and len(lines) < h:
            lines.append((f"  {n['ipv6']}", C_USB, curses.A_DIM))
        if not is_down and len(lines) < h:
            lines.append((f"  tx{fb(n['tx']):>5}/s  rx{fb(n['rx']):>5}/s", C_DISK))
        if n['is_wifi'] and len(lines) < h:
            ssid = n['ssid'] if n['ssid'] else ('(disconnected)' if is_down else '(no SSID)')
            sig  = f"  {n['signal']}dB" if n.get('signal') else ''
            lines.append((f"  SSID: {ssid}{sig}", C_SEL, curses.A_DIM if is_down else 0))
    # Bluetooth
    if len(lines) < h:
        if bt:
            for dev in bt[:2]:
                if len(lines) >= h: break
                lines.append((f"Bluetooth: {dev}", C_USB))
        else:
            lines.append(('Bluetooth: none', C_WARN))
    return lines

def col_usb(usb, h):
    lines = []
    for u in usb[:h]:
        lines.append((f"USB {u['name']}", C_DISK))
    if not usb:
        lines.append(('no USB devices', C_USB, curses.A_DIM))
    return lines

def col_hooks(hooks, h):
    lines = []
    if not hooks:
        lines.append(('hooks: ~/.config/bsc/hooks/', C_USB, curses.A_DIM))
        return lines
    for hname, hlines in hooks.items():
        if len(lines) >= h: break
        lines.append((f"── {hname}", C_DISK, curses.A_BOLD))
        for hl in hlines:
            if len(lines) >= h: break
            lines.append((hl, C_DISK))
    return lines

def _count_bwrap():
    n = 0
    for d in os.listdir('/proc'):
        try:
            if open(f'/proc/{d}/comm').read().strip() == 'bwrap': n += 1
        except: pass
    return n

def col_audio_usb(aud, cards, usb, removable, h):
    lines = col_audio(aud, cards, h)
    if len(lines) < h:
        lines.append(('─── USB', C_HDR))
    for u in usb[:max(0, h - len(lines))]:
        lines.append((f"USB {u['name']}", C_DISK))
    if not usb and len(lines) < h:
        lines.append(('no USB devices', C_USB, curses.A_DIM))
    # removable storage: USB drives, SD, optical
    for d in removable[:max(0, h - len(lines))]:
        if len(lines) >= h: break
        dev = d['dev']
        if d['is_optical']:
            disc_s = 'disc' if d.get('size_b', 0) > 0 else 'empty'
            kind = 'CD/DVD/BD'
            lines.append((f"{dev}  {kind}  [{disc_s}]", C_DISK))
        else:
            sz_s  = fb(d.get('size_b', 0)) if d.get('size_b') else '?'
            model = _disk_model(dev)
            rot   = d.get('rotational')
            sched = _disk_scheduler(dev)
            kind  = 'USB-HDD' if rot else ('USB-SD' if dev.startswith('mmcblk') else 'USB')
            hdr   = f"{kind} {dev} {sz_s}"
            if model: hdr += f"  {model[:14]}"
            if sched: hdr += f"  [{sched}]"
            lines.append((hdr, C_DISK))
            if len(lines) < h:
                idle = d.get('rd',0) < 1024 and d.get('wr',0) < 1024
                lines.append((
                    f"  i{fb(d.get('rd',0)):>5}/s o{fb(d.get('wr',0)):>5}/s  busy:{d.get('busy',0):2.0f}%",
                    C_DISK, curses.A_DIM if idle else 0))
        for i, part in enumerate(d.get('parts', [])):
            if len(lines) >= h: break
            pct  = pct2(part['used'], part['total'])
            clr  = _pct_color(pct)
            tree = '└' if i == len(d['parts'])-1 else '├'
            mp   = part['mp'] or '--'
            fs_t = part.get('fs','?')[:6]
            lines.append((
                f" {tree}{part['part']:<8}{mp:<9}{fs_t:<6}"
                f"{fmt_mem(part['used']//1024):>5}/{fmt_mem(part['total']//1024):<5} {pct:3d}%",
                clr))
    return lines

def _short_uptime(s):
    # "3 weeks ago" → "3w", "5 hours ago" → "5h", "2 months ago" → "2mon", "1 year ago" → "1y"
    if not s: return ''
    s = s.lower()
    for word, abbr in [('weeks','w'),('week','w'),('months','mon'),('month','mon'),
                       ('years','y'),('year','y'),('days','d'),('day','d'),
                       ('hours','h'),('hour','h'),('minutes','min'),('minute','min'),
                       ('seconds','s'),('second','s')]:
        s = s.replace(word, abbr)
    s = s.replace(' ago','').strip()
    # collapse "3 w" → "3w", "2 mon" → "2mon"
    import re as _re
    s = _re.sub(r'(\d+)\s+([a-z]+)', r'\1\2', s)
    return s

def col_vms(vms, h):
    lines = []
    kvm = vms.get('kvm', {})
    kvm_s = f"KVM: {kvm.get('vendor','?')}  {'ok' if kvm.get('avail') else 'no'} /dev/kvm"
    lines.append((kvm_s, C_DISK if kvm.get('avail') else C_WARN))

    ST_CLR = {'run': C_DISK, 'pause': C_RAM, 'stop': C_USB, 'new': C_NET, 'running': C_DISK}

    # (data_key, display_label, binary_to_check, show_rss)
    sections = [
        ('qemu',        'QEMU',        'qemu-system-x86_64', True),
        ('vbox',        'VirtualBox',  'VBoxHeadless',       False),
        ('vmware',      'VMware',      'vmware-vmx',         False),
        ('proxmox_vms', 'Proxmox VM',  'qm',                 False),
        ('proxmox_lxc', 'Proxmox LXC', 'pct',                False),
        ('docker',      'Docker',      'docker',             False),
        ('podman',      'Podman',      'podman',             False),
    ]
    for key, label, binary, show_rss in sections:
        items    = vms.get(key, [])
        installed = bool(shutil.which(binary))
        if len(lines) >= h: break
        if not items:
            # not installed: dim row; installed but empty: green "label: 0"
            if installed:
                lines.append((f"{label}: 0", C_DISK))
            else:
                lines.append((label, C_USB, curses.A_DIM))
            continue
        run_n = sum(1 for x in items if x['status'] in ('run', 'running'))
        lines.append((f"{label}: {run_n}/{len(items)}", C_DISK))
        for i, vm in enumerate(items):
            if len(lines) >= h: break
            tree = '└' if i == len(items)-1 else '├'
            st   = vm['status']
            clr  = ST_CLR.get(st, C_USB)
            attr = curses.A_DIM if st in ('stop', 'stopped') else 0
            extra = ''
            if show_rss and vm.get('rss_kb'):
                extra = f" {fmt_mem(vm['rss_kb'])}"
            if vm.get('running_for'):
                extra += f" {_short_uptime(vm['running_for'])}"
            elif vm.get('id'):
                extra += f" {vm['id'][:8]}"
            if vm.get('exit_code') and st in ('stop', 'stopped'):
                extra += f" ec:{vm['exit_code']}"
            lines.append((f" {tree}{vm['name']:<14}[{st[:3]}]{extra}", clr, attr))

    if len(lines) < h:
        bwn = _count_bwrap()
        bw_installed = bool(shutil.which('bwrap'))
        if bw_installed:
            lines.append((f"Bubblewrap: {bwn}", C_DISK))
        else:
            lines.append(('Bubblewrap', C_USB, curses.A_DIM))

    if len(lines) < h:
        fw = _firewall_status()
        if fw and fw != ['none']:
            lines.append((f"Firewall: {' '.join(fw)}", C_DISK))
        else:
            lines.append(('Firewall', C_USB, curses.A_DIM))

    if len(lines) < h:
        sb = _sandbox_status()
        if sb and sb != ['none']:
            lines.append((f"Sandbox: {' '.join(sb)}", C_GPU))
        else:
            lines.append(('Sandbox', C_USB, curses.A_DIM))

    return lines

# ── render helpers ─────────────────────────────────────────────────────────

def render_cols(stdscr, cols_data, col_widths, start_row, max_rows):
    for row_i in range(max_rows):
        x = 0
        for ci, lines in enumerate(cols_data):
            w = col_widths[ci]
            content_w = w - 1
            if row_i < len(lines):
                row  = lines[row_i]
                text = row[0]
                cp   = row[1]
                attr = row[2] if len(row) > 2 else 0
                put(stdscr, start_row + row_i, x, text[:content_w].ljust(content_w),
                    curses.color_pair(cp) | attr)
            else:
                put(stdscr, start_row + row_i, x, ' ' * content_w)
            if ci < len(cols_data) - 1:
                put(stdscr, start_row + row_i, x + content_w, '│',
                    curses.color_pair(C_HDR) | curses.A_DIM)
            x += w

def draw_rec_indicator(stdscr, H, W, state):
    rec = state.get('rec')
    if not rec: return
    elapsed = int(time.time() - rec['start'])
    lbl = f" ●REC {elapsed//60:02d}:{elapsed%60:02d} "
    put(stdscr, 0, max(0, W - len(lbl)), lbl,
        curses.color_pair(C_WARN) | curses.A_BOLD)

def draw_legend(stdscr, H, W, items):
    # row H-2: colored block + label pairs showing what each color means
    row = H - 2
    x   = 0
    for cp, lbl in items:
        seg = f"█{lbl} "
        if x + len(seg) >= W: break
        put(stdscr, row, x,   '█', curses.color_pair(cp))
        put(stdscr, row, x+1, f"{lbl} ", curses.color_pair(C_USB) | curses.A_DIM)
        x += len(seg)

def draw_statusbar(stdscr, state):
    H, W = stdscr.getmaxyx()
    tab_s    = "[1=OVW 2=DEV 3=HEX Tab] q=quit +/-=ms R=rec y=copy"
    battery  = state.get('battery', {})
    uptime_s = state.get('uptime_s', '')
    interval = state.get('interval_ms', 1000)
    rec      = state.get('rec')
    bat_s = ''
    if battery:
        pct   = battery.get('pct', 0)
        ac    = battery.get('ac', False)
        stat  = battery.get('status', '')
        arrow = '+' if stat == 'Charging' else ('-' if stat == 'Discharging' else '=')
        bat_s = f"BAT:{pct}%{arrow} {'AC' if ac else 'BAT'}"
    else:
        bat_s = "no bat"
    date_s = time.strftime('%Y-%m-%d %H:%M')
    right = f"├ {bat_s} | up:{uptime_s} | {date_s} | {interval}ms ─┤"
    left  = f" {tab_s} "
    gap   = max(1, W - len(left) - len(right))
    bar   = (left + ' ' * gap + right)[:W]
    put(stdscr, H-1, 0, bar, curses.A_REVERSE)
    # REC indicator — overdraw with red+bold so it's unmissable
    if rec:
        elapsed  = int(time.time() - rec['start'])
        rec_lbl  = f" ●REC {elapsed//60:02d}:{elapsed%60:02d} "
        rec_x    = max(0, W - len(right) - len(rec_lbl))
        put(stdscr, H-1, rec_x, rec_lbl,
            curses.color_pair(C_WARN) | curses.A_BOLD | curses.A_REVERSE)

def draw_pid_panel(stdscr, pid, col_x, pw, top_row, H):
    # right-side panel: dense /proc/PID/* details, drawn live every frame
    pid_s = str(pid)
    row   = top_row
    gc = curses.color_pair(C_DISK)
    dc = curses.color_pair(C_USB) | curses.A_DIM
    hc = curses.color_pair(C_SEL) | curses.A_BOLD

    # vertical separator — starts at top_h row, not row 0 (don't overlap overview columns)
    for r in range(top_row, H - 2):
        put(stdscr, r, col_x - 1, '│', curses.color_pair(C_HDR) | curses.A_DIM)

    def pp(text, attr=0):
        nonlocal row
        if row >= H - 2: return
        put(stdscr, row, col_x, text[:pw], attr); row += 1

    # cmdline
    try:    cmd = open(f'/proc/{pid_s}/cmdline').read().replace('\x00', ' ').strip()
    except: cmd = '?'
    pp(f"PID {pid}  {cmd}", hc)

    # /proc/PID/status
    try:
        st = {}
        for l in open(f'/proc/{pid_s}/status', errors='replace'):
            k, _, v = l.partition(':'); st[k.strip()] = v.strip()
        rss  = int(st.get('VmRSS','0 kB').split()[0]) * 1024
        virt = int(st.get('VmSize','0 kB').split()[0]) * 1024
        peak = int(st.get('VmPeak','0 kB').split()[0]) * 1024
        pp(f"state:{st.get('State','?')}  ppid:{st.get('PPid','?')}  uid:{st.get('Uid','?').split()[0]}  thr:{st.get('Threads','?')}", gc)
        pp(f"rss:{fb(rss)}  virt:{fb(virt)}  peak:{fb(peak)}", gc)
        cv = st.get('voluntary_ctxt_switches','?')
        ci = st.get('nonvoluntary_ctxt_switches','?')
        pp(f"ctx:{cv}vol/{ci}inv  cap:{st.get('CapEff','?')}", dc)
    except: pass

    # /proc/PID/io
    try:
        io = {}
        for l in open(f'/proc/{pid_s}/io'):
            k, _, v = l.partition(':'); io[k.strip()] = v.strip()
        pp(f"io r:{fb(int(io.get('rchar','0')))} w:{fb(int(io.get('wchar','0')))}  "
           f"blk r:{fb(int(io.get('read_bytes','0')))} w:{fb(int(io.get('write_bytes','0')))}", gc)
    except: pass

    # wchan + current syscall
    try:
        wchan = open(f'/proc/{pid_s}/wchan').read().strip()
        sc    = open(f'/proc/{pid_s}/syscall').read().split()
        if sc and sc[0] == 'running':
            pp(f"wchan:{wchan}  running (userspace)", gc)
        elif sc and len(sc) >= 9:
            name = _SYSCALL_NAMES.get(int(sc[0]), f'sys_{sc[0]}')
            pp(f"wchan:{wchan}  syscall:{name}({sc[0]})", gc)
            pp(f"  rdi:{sc[1]}  rsi:{sc[2]}  rdx:{sc[3]}", dc)
            pp(f"  rsp:{sc[7]}  rip:{sc[8]}", dc)
    except: pass

    # open fds — count + first few targets
    try:
        fds = sorted(os.listdir(f'/proc/{pid_s}/fd'),
                     key=lambda x: int(x) if x.isdigit() else 9999)
        pp(f"fds:{len(fds)}", gc)
        for fd in fds[:min(6, H - row - 6)]:
            try:
                tgt = os.readlink(f'/proc/{pid_s}/fd/{fd}')
                pp(f"  {fd:>3}→{tgt}", dc)
            except: pass
    except: pass

    # maps summary
    try:
        maps  = open(f'/proc/{pid_s}/maps').readlines()
        execs = sum(1 for l in maps if len(l.split()) > 1 and 'x' in l.split()[1])
        pp(f"maps:{len(maps)}  exec:{execs}", dc)
    except: pass

    # oom + cgroup + namespaces
    try:
        oom     = open(f'/proc/{pid_s}/oom_score').read().strip()
        oom_adj = open(f'/proc/{pid_s}/oom_score_adj').read().strip()
        pp(f"oom:{oom}  adj:{oom_adj}", dc)
    except: pass
    try:
        cg = open(f'/proc/{pid_s}/cgroup').readline().strip().split(':')[-1]
        pp(f"cg:{cg}", dc)
    except: pass
    try:
        ns = sorted(os.listdir(f'/proc/{pid_s}/ns'))
        pp(f"ns:{' '.join(ns)}", dc)
    except: pass

# ── TAB 0: OVERVIEW ────────────────────────────────────────────────────────

def draw_main(stdscr, state):
    stdscr.erase()
    H, W = stdscr.getmaxyx()

    cores, load, _ = state['cpu']
    rapl_w  = state.get('rapl_w', 0.0)
    top_h   = max(10, min(H // 2, 22))

    aud_detail = state.get('audio_detail', {})
    sections = [
        ('cpurg',   28, lambda w: col_cpu_ram_gpu(cores, load, rapl_w, state['mem'], state['gpu'], top_h)),
        ('disk',    32, lambda w: col_disk(state['disk'], top_h)),
        ('net',     44, lambda w: col_net(state['net'], state.get('bt',[]), top_h, state.get('net_scroll',0))),
        ('audusb',  28, lambda w: col_audio_usb(aud_detail, state['audio'], state['usb'], state.get('removable',[]), top_h)),
        ('vms',     22, lambda w: col_vms(state.get('vms',{}), top_h)),
        ('hooks',   18, lambda w: col_hooks(state.get('hooks',{}), top_h)),
    ]

    min_total = sum(s[1] for s in sections)
    if   W >= min_total:                                     chosen = sections
    elif W >= min_total - sections[5][1]:                    chosen = sections[:5]
    elif W >= min_total - sections[5][1] - sections[4][1]:  chosen = sections[:4]
    elif W >= sections[0][1] + sections[1][1] + sections[2][1]: chosen = sections[:3]
    elif W >= 60:  chosen = [sections[0], sections[1], sections[2]]
    else:          chosen = [sections[0]]

    cols_data  = [s[2](W) for s in chosen]
    col_widths = [max((len(row[0]) for row in lines), default=8) + 1 for lines in cols_data]

    total = sum(col_widths)
    for trim_target in ('hooks', 'vms', 'audusb', 'net', 'disk'):
        if total <= W: break
        for i, s in enumerate(chosen):
            if s[0] == trim_target and total > W:
                col_widths[i] = max(s[1], col_widths[i] - (total - W))
                total = sum(col_widths)

    remainder = W - sum(col_widths)
    for extra_target in ('hooks', 'net', 'disk'):
        for i, s in enumerate(chosen):
            if s[0] == extra_target and remainder > 0:
                col_widths[i] += remainder; remainder = 0

    render_cols(stdscr, cols_data, col_widths, 0, top_h)

    # ── proc section (bottom half) ──────────────────────────────────────────
    procs       = state.get('procs', [])
    proc_counts = state.get('proc_counts', {})
    sel         = state.get('sel', 0)
    scroll      = state.get('scroll', 0)
    filt        = state.get('filt', 'user')
    sort        = state.get('sort', 'cpu')
    marked      = state.get('marked', set())
    input_mode  = state.get('input_mode', False)
    input_buf   = state.get('input_buf', '')
    search      = state.get('search', '')
    search_mode = state.get('search_mode', False)
    view_pid    = state.get('view_pid', None)
    list_w      = (W // 2) if view_pid else W   # narrow list when panel open

    rn = proc_counts.get('R',0); sn = proc_counts.get('S',0)
    dn = proc_counts.get('D',0); zn = proc_counts.get('Z',0)
    stats  = f"R:{rn} S:{sn} D:{dn} Z:{zn}"
    fl     = f"◄ {filt} ►"
    sl     = sort.upper()
    srch   = f" /{search}_" if search_mode else (f" /{search}" if search else "")
    bar_w  = list_w - len(fl) - len(sl) - len(stats) - len(srch) - 14
    put(stdscr, top_h, 0,
        (f" PROC [{fl}]{srch}" + "─"*max(0,bar_w) + f"[{stats}][{sl}] ")[:list_w],
        curses.color_pair(C_HDR) | curses.A_BOLD)

    put(stdscr, top_h+1, 0, f"  {'PID':>6}  {'CPU%':>5}  {'MEM':>6}  T  CMD"[:list_w])

    list_start = top_h + 2
    avail = H - list_start - 3
    if input_mode: avail -= 1

    for i, p in enumerate(procs[scroll:scroll+avail]):
        abs_i     = scroll + i
        is_sel    = abs_i == sel
        is_marked = p['pid'] in marked
        is_kern   = bool(KERN_RE.match(p.get('name','') or ''))
        is_zombie = p.get('tc','') == 'Z'
        if is_sel:           attr = curses.color_pair(C_CPU) | curses.A_BOLD
        elif is_marked:      attr = curses.color_pair(C_MARK)
        elif is_zombie:      attr = curses.color_pair(C_WARN) | curses.A_BOLD
        elif is_kern:        attr = curses.color_pair(C_USB) | curses.A_DIM
        elif p['cpu'] >= 20: attr = curses.color_pair(C_WARN)
        elif p['cpu'] >= 5:  attr = curses.color_pair(C_RAM)
        else:                attr = curses.color_pair(C_DISK)
        mark_c = '●' if is_marked else ' '
        cmd    = (p['cmd'] or p['name'])[:list_w - 33]
        put(stdscr, list_start+i, 0,
            f"{mark_c} {p['pid']:>6}  {p['cpu']:5.1f}  {kbs(p['mem_kb']):>6}  {p['tc']}  {cmd}"[:list_w], attr)

    if view_pid:
        draw_pid_panel(stdscr, view_pid, W // 2 + 1, W - W // 2 - 1, top_h, H)

    if input_mode:
        put(stdscr, H-3, 0, f"[:cmd] {input_buf}_"[:W], curses.color_pair(C_SEL))

    draw_legend(stdscr, H, W, [(C_WARN,'high'),(C_RAM,'med'),(C_DISK,'low'),(C_USB,'kern'),(C_CPU,'sel'),(C_NET,'NET')])
    proc_hints = "  ↑↓=sel  Enter/v=view  d=trace→DEV  Esc=close  ←→=flt  c=cpu  m=mem  k=kill  9=SIGKILL  /=search  y=copy"
    put(stdscr, H-2, min(W-1, 38), proc_hints[:max(0, W-38)], curses.color_pair(C_USB) | curses.A_DIM)
    draw_rec_indicator(stdscr, H, W, state)
    draw_statusbar(stdscr, state)
    _refresh(stdscr)

# ── TAB 1: DEV ────────────────────────────────────────────────────────────

def draw_dev(stdscr, state):
    global _prev_dev
    stdscr.erase()
    H, W = stdscr.getmaxyx()
    d  = read_dev_global()
    mi = d.get('mi', {})
    row = 0

    put(stdscr, row, 0,
        (f" DEV " + "─"*(W-6))[:W],
        curses.color_pair(C_HDR) | curses.A_BOLD)
    row += 1

    # MEMORY MAP — coloured segments
    put(stdscr, row, 0, ("─── MEMORY MAP " + "─"*(W-15))[:W], curses.color_pair(C_HDR)); row += 1
    tot_kb = mi.get('MemTotal', 1)
    segs = [
        ('kern', mi.get('KernelStack',0)+mi.get('Slab',0)+mi.get('PageTables',0), C_WARN,  'K'),
        ('huge', mi.get('HugePages_Total',0)*2048,                                 C_GPU,   'H'),
        ('anon', mi.get('Active(anon)',0)+mi.get('Inactive(anon)',0)+mi.get('Shmem',0), C_RAM, 'A'),
        ('cach', mi.get('Buffers',0)+mi.get('Cached',0),                           C_DISK,  'C'),
        ('swap', mi.get('SwapTotal',0)-mi.get('SwapFree',0),                       C_ZRAM,  'S'),
        ('free', mi.get('MemFree',0),                                               C_NET,   '.'),
    ]
    map_w = max(1, W - 2)
    # compute pixel widths first — used for both bar rows and label row
    seg_widths = []
    for lbl, kb, cp, ch in segs:
        n = max(0, round(kb * map_w / tot_kb))
        seg_widths.append(n)
    # bar row — show % inside each segment
    x = 1
    for si, (lbl, kb, cp, ch) in enumerate(segs):
        n = seg_widths[si]
        if n == 0 or x >= W - 1: continue
        pct = int(100 * kb / tot_kb) if tot_kb else 0
        label = f"{pct}%" if n >= 4 else ' ' * n
        pad   = n - len(label)
        block = ' ' * (pad // 2) + label + ' ' * (pad - pad // 2)
        try: stdscr.addstr(row, x, block[:W-1-x], curses.color_pair(cp) | curses.A_REVERSE)
        except: pass
        x += n
    if x < W - 1:
        try: stdscr.addstr(row, x, ' ' * (W-1-x), curses.color_pair(C_NET) | curses.A_REVERSE)
        except: pass
    row += 1
    # label row — colored names aligned under their segments
    x = 1
    for si, (lbl, kb, cp, ch) in enumerate(segs):
        n = seg_widths[si]
        if n == 0 or x >= W - 1: continue
        s = lbl[:n].ljust(n) if n >= len(lbl) else ' ' * n
        try: stdscr.addstr(row, x, s[:W-1-x], curses.color_pair(cp))
        except: pass
        x += n
    row += 1
    # value row — KB sizes aligned under segments
    x = 1
    for si, (lbl, kb, cp, ch) in enumerate(segs):
        n = seg_widths[si]
        if n == 0 or x >= W - 1: continue
        kb_s = fmt_mem(kb)
        s    = kb_s[:n].ljust(n) if n >= len(kb_s) else ' ' * n
        try: stdscr.addstr(row, x, s[:W-1-x], curses.color_pair(C_USB) | curses.A_DIM)
        except: pass
        x += n
    row += 1
    # stats row
    pgf   = d.get('pgfault',0) - _prev_dev.get('pgfault',0)
    hp_f  = d.get('hugepages_free',0); hp_t = d.get('hugepages_total',0)
    put(stdscr, row, 0,
        (f" total:{fmt_mem(tot_kb)}  faults:{pgf}/s"
         f"  dirty:{fmt_mem(d.get('dirty',0))}  wb:{fmt_mem(d.get('writeback',0))}"
         f"  huge:{hp_t-hp_f}/{hp_t}")[:W],
        curses.color_pair(C_DISK)); row += 2

    # SCHEDULER
    if row < H - 8:
        put(stdscr, row, 0, ("─── SCHEDULER " + "─"*(W-14))[:W], curses.color_pair(C_HDR)); row += 1
        sw_now   = d.get('nr_switches', 0)
        sw_prev  = _prev_dev.get('nr_switches', sw_now)
        sw_rate  = sw_now - sw_prev
        swap_in  = d.get('pswpin', 0)  - _prev_dev.get('pswpin', 0)
        swap_out = d.get('pswpout', 0) - _prev_dev.get('pswpout', 0)
        put(stdscr, row, 0,
            f" ctx_switches:{sw_rate}/s  swap_in:{swap_in}  swap_out:{swap_out}"[:W],
            curses.color_pair(C_DISK)); row += 1

    # KERNEL TUNABLES
    if row < H - 8:
        put(stdscr, row, 0, ("─── KERNEL TUNABLES " + "─"*(W-20))[:W], curses.color_pair(C_HDR)); row += 1
        tunables = [
            ('/proc/sys/vm/swappiness',                  'swappiness'),
            ('/proc/sys/vm/dirty_ratio',                 'dirty_ratio'),
            ('/proc/sys/vm/dirty_background_ratio',      'dirty_bg'),
            ('/proc/sys/net/core/somaxconn',             'somaxconn'),
            ('/proc/sys/net/ipv4/tcp_max_syn_backlog',   'syn_backlog'),
            ('/proc/sys/kernel/pid_max',                 'pid_max'),
            ('/proc/sys/kernel/random/entropy_avail',    'entropy'),
            ('/proc/sys/fs/file-nr',                     'fd_used/max'),
        ]
        tline = []
        for path, lbl in tunables:
            try:
                val = open(path).read().strip().replace('\t','/')
                tline.append(f"{lbl}:{val}")
            except: pass
            if len(tline) == 4:
                if row < H - 3: put(stdscr, row, 0, ('  ' + '  '.join(tline))[:W], curses.color_pair(C_DISK)); row += 1
                tline = []
        if tline and row < H - 3:
            put(stdscr, row, 0, ('  ' + '  '.join(tline))[:W], curses.color_pair(C_DISK)); row += 1

    # CPU FLAGS — all present (green), missing power-user set (red)
    if row < H - 5:
        put(stdscr, row, 0, ("─── CPU FLAGS " + "─"*(W-14))[:W], curses.color_pair(C_HDR)); row += 1
        try:
            all_flags = []
            for l in open('/proc/cpuinfo'):
                if l.startswith('flags'):
                    all_flags = sorted(l.split(':', 1)[1].split()); break
            flags_set = set(all_flags)
            line_buf = ''
            for f in all_flags:
                if len(line_buf) + len(f) + 1 > W - 1:
                    if row < H - 3:
                        put(stdscr, row, 0, line_buf[:W], curses.color_pair(C_DISK)); row += 1
                    line_buf = f
                else:
                    line_buf = (line_buf + ' ' + f).lstrip()
            if line_buf and row < H - 3:
                put(stdscr, row, 0, line_buf[:W], curses.color_pair(C_DISK)); row += 1
            # missing from useful reference set — shown in red, no separator
            want = [
                # baseline x86_64
                'fpu','vme','de','pse','tsc','msr','pae','mce','cx8','apic',
                'sep','mtrr','pge','mca','cmov','pat','pse36','clflush','mmx',
                'fxsr','sse','sse2','ss','ht','syscall','nx','lm','nopl',
                # SSE/AVX family
                'pni','ssse3','cx16','sse4_1','sse4_2','popcnt',
                'avx','avx2','avx512f','avx512dq','avx512bw','avx512vl',
                'avx512cd','avx512ifma','avx512vbmi','avx512_vnni',
                'f16c','fma',
                # crypto / security primitives
                'aes','pclmulqdq','sha_ni','rdrand','rdseed',
                'smep','smap','umip','pku',
                # virt
                'vmx','svm','ept','vpid',
                # bit manip
                'bmi1','bmi2','adx','abm','lzcnt','movbe',
                # memory
                'pdpe1gb','rdtscp','xsave','xsaveopt','xsavec','xgetbv1',
                'clflushopt','clwb','erms','invpcid','fsgsbase',
                # spectre/meltdown mitigations (show absence as important)
                'ibrs','ibpb','stibp','ssbd','retpoline',
                # perf/debug
                'tsc_deadline_timer','dca','ds_cpl','dtes64',
            ]
            absent = sorted(f for f in want if f not in flags_set)
            line_buf = ''
            for f in absent:
                if len(line_buf) + len(f) + 1 > W - 1:
                    if row < H - 3:
                        put(stdscr, row, 0, line_buf[:W], curses.color_pair(C_WARN)); row += 1
                    line_buf = f
                else:
                    line_buf = (line_buf + ' ' + f).lstrip()
            if line_buf and row < H - 3:
                put(stdscr, row, 0, line_buf[:W], curses.color_pair(C_WARN)); row += 1
        except: pass

    # TOP IRQs
    if row < H - 6:
        put(stdscr, row, 0, ("─── TOP IRQs " + "─"*(W-13))[:W], curses.color_pair(C_HDR)); row += 1
        irqs = []
        try:
            lines_irq = open('/proc/interrupts').readlines()
            cpu_n = len(lines_irq[0].split())
            for l in lines_irq[1:]:
                p = l.split()
                if len(p) < cpu_n + 1: continue
                try:
                    total = sum(int(p[i]) for i in range(1, cpu_n+1))
                    name  = ' '.join(p[cpu_n+1:])[:20]
                    irqs.append((total, p[0].rstrip(':'), name))
                except: pass
        except: pass
        for total, irq_n, name in sorted(irqs, reverse=True)[:4]:
            if row >= H - 3: break
            put(stdscr, row, 0, f"  {irq_n:<6} {total:>10}  {name}"[:W], curses.color_pair(C_DISK)); row += 1

    # KERNEL LOG (last lines from /dev/kmsg)
    if row < H - 5:
        put(stdscr, row, 0, ("─── KERNEL LOG " + "─"*(W-15))[:W], curses.color_pair(C_HDR)); row += 1
        kmsgs = []
        try:
            import subprocess as _sp
            out = _sp.check_output(['dmesg', '--time-format=reltime', '-n', 'warn', '--level=err,warn', '-T'],
                                   timeout=1, stderr=_sp.DEVNULL).decode(errors='replace')
            kmsgs = out.strip().splitlines()[-4:]
        except:
            try:
                with open('/dev/kmsg', 'rb') as km:
                    import fcntl, os as _os
                    fcntl.fcntl(km, fcntl.F_SETFL, _os.O_NONBLOCK)
                    buf = km.read(8192)
                    for l in buf.decode(errors='replace').splitlines()[-4:]:
                        p = l.split(';', 1)
                        kmsgs.append(p[-1][:80] if p else l[:80])
            except: pass
        if not kmsgs:
            if row < H - 3:
                put(stdscr, row, 0, "  (no recent warnings)"[:W], curses.color_pair(C_DISK)); row += 1
        else:
            for km_line in kmsgs[-3:]:
                if row >= H - 3: break
                put(stdscr, row, 0, f"  {km_line.strip()}"[:W], curses.color_pair(C_WARN) | curses.A_DIM); row += 1

    # PID DETAILS (if selected)
    sel_pid = state.get('sel_pid', '')
    if sel_pid and row < H - 5:
        put(stdscr, row, 0, (f"─── PID {sel_pid} DETAILS " + "─"*(W-20))[:W], curses.color_pair(C_HDR)); row += 1
        try:
            oom  = open(f'/proc/{sel_pid}/oom_score').read().strip()
            oom_adj = open(f'/proc/{sel_pid}/oom_score_adj').read().strip()
            ns_line = ' '.join(os.listdir(f'/proc/{sel_pid}/ns'))
            cg = open(f'/proc/{sel_pid}/cgroup').readline().strip().split(':')[-1]
            put(stdscr, row, 0, f"  oom:{oom} adj:{oom_adj}  cg:{cg}"[:W], curses.color_pair(C_DISK)); row += 1
            if row < H - 3:
                put(stdscr, row, 0, f"  ns: {ns_line}"[:W], curses.color_pair(C_DISK) | curses.A_DIM); row += 1
        except: pass

    # REGISTERS + DISASM — /proc/PID/syscall: NR rdi rsi rdx r10 r8 r9 rsp rip
    # available only while process is inside a syscall (not while running userspace)
    if sel_pid and row < H - 5:
        put(stdscr, row, 0, (f"─── REGISTERS & DISASM " + "─"*(W-23))[:W],
            curses.color_pair(C_HDR)); row += 1
    try:
        sc_raw = open(f'/proc/{sel_pid}/syscall').read().split()
        if len(sc_raw) == 9 and sc_raw[0] != 'running':
            # x86_64 syscall ABI register names
            names = ['rax','rdi','rsi','rdx','r10','r8 ','r9 ','rsp','rip']
            vals  = sc_raw
            # show 3 regs per line so long hex addresses still fit
            pairs = [f"{names[j]}:{vals[j]}" for j in range(9)]
            per_line = max(1, W // 30)
            for chunk_s in range(0, len(pairs), per_line):
                if row >= H - 3: break
                put(stdscr, row, 0, ('  ' + '  '.join(pairs[chunk_s:chunk_s+per_line]))[:W],
                    curses.color_pair(C_DISK)); row += 1
            # syscall name from rax
            try:
                nr  = int(sc_raw[0])
                snm = _SYSCALL_NAMES.get(nr, f'sys_{nr}')
                if row < H - 3:
                    put(stdscr, row, 0, f"  syscall: {snm}({nr})"[:W],
                        curses.color_pair(C_SEL)); row += 1
            except: pass
            # disassembly at rip
            try:
                rip = int(sc_raw[8], 16)
                if row < H - 5:
                    put(stdscr, row, 0, f"  disasm @ rip {sc_raw[8]}:"[:W],
                        curses.color_pair(C_USB) | curses.A_DIM); row += 1
                    avail = H - row - 3
                    for dline in _disasm(str(sel_pid), rip, n_insn=avail):
                        if row >= H - 3: break
                        put(stdscr, row, 0, dline[:W], curses.color_pair(C_DISK)); row += 1
            except: pass
        elif sc_raw and sc_raw[0] == 'running':
            if row < H - 3:
                put(stdscr, row, 0, "  [running in userspace — regs visible only during syscall]"[:W],
                    curses.color_pair(C_USB) | curses.A_DIM); row += 1
    except: pass

    # SYSCALL TRACE — multi-core columns, 10ms sampler / eBPF / perf
    _core_sampler_start()
    global _core_watch, _prev_ring_len
    n_cores = len(state.get('cpu', ([],))[0]) or 1
    if   _bpf_proc  and _bpf_proc.poll()  is None: backend_lbl = 'eBPF'
    elif _perf_proc and _perf_proc.poll() is None: backend_lbl = 'perf'
    else: backend_lbl = '/proc'
    # adaptive column count: 3 if wide, 2 if medium, 1 if narrow
    # always fill n_cols fully — clamp core_n so core_n+n_cols-1 < n_cores
    n_cols  = 3 if W >= 150 else 2 if W >= 80 else 1
    n_cols  = min(n_cols, n_cores)
    core_n  = min(state.get('core_trace', 0), max(0, n_cores - n_cols))
    state['core_trace'] = core_n  # snap back if clamped
    _core_watch = core_n
    col_w   = W // n_cols
    avail_sc = max(0, H - row - 4)  # rows available for trace entries (minus header+hints)
    # max_scroll: how far we can scroll without blank lines at bottom
    max_scroll = max(0, max(
        (len(_core_rings.get(core_n + c, collections.deque())) for c in range(n_cols)),
        default=0) - avail_sc)
    sc_scroll = min(state.get('dev_scroll', 0), max_scroll)
    # anchor: if user has scrolled back, advance sc_scroll as new entries arrive
    # so the currently visible entry stays in place (no jump on ctx switch)
    if sc_scroll > 0:
        for c in range(n_cols):
            cn = core_n + c
            cur_len = len(_core_rings.get(cn, collections.deque()))
            delta = cur_len - _prev_ring_len.get(cn, cur_len)
            if delta > 0:
                sc_scroll = min(sc_scroll + delta, max_scroll)
    state['dev_scroll'] = sc_scroll
    # update prev lengths for next frame
    for c in range(n_cols):
        cn = core_n + c
        _prev_ring_len[cn] = len(_core_rings.get(cn, collections.deque()))
    if row < H - 5:
        cores_s = '-'.join(str(core_n + c) for c in range(n_cols))
        put(stdscr, row, 0,
            (f"─── SYSCALL TRACE [cores {cores_s}/{n_cores-1}] [{backend_lbl}] [←→=shift ↑↓=scroll] " + "─"*(W-20))[:W],
            curses.color_pair(C_HDR))
        row += 1
    # draw column headers
    if row < H - 3:
        for c in range(n_cols):
            cn = core_n + c
            r  = _core_rings.get(cn, collections.deque())
            put(stdscr, row, c * col_w, f" core {cn} [{len(r)}]"[:col_w], curses.color_pair(C_HDR) | curses.A_BOLD)
        row += 1
    # draw entries side by side — newest first (reversed), sc_scroll offsets from newest
    for ri in range(avail_sc):
        r = row + ri
        if r >= H - 2: break
        for c in range(n_cols):
            cn      = core_n + c
            entries = list(reversed(_core_rings.get(cn, collections.deque())))
            idx     = sc_scroll + ri
            if idx >= len(entries): continue
            sc_line = entries[idx]
            x0 = c * col_w
            if ' ×' in sc_line:
                base, _, cnt = sc_line.rpartition(' ×')
                put(stdscr, r, x0,              base[:col_w-6],             curses.color_pair(C_DISK))
                put(stdscr, r, x0 + len(base[:col_w-6]), f' ×{cnt}'[:6],   curses.color_pair(C_SEL))
            else:
                put(stdscr, r, x0, sc_line[:col_w-1], curses.color_pair(C_DISK))

    _prev_dev.update({k: v for k, v in d.items() if isinstance(v, int)})
    sc_pos = state.get('dev_scroll', 0)
    hint = f" ←→=shift cores [{core_n}..{core_n+n_cols-1}]  ↑↓=scroll [{sc_pos}]  [{backend_lbl}]"
    put(stdscr, H-2, 0, hint[:W], curses.color_pair(C_DISK))
    draw_rec_indicator(stdscr, H, W, state)
    draw_statusbar(stdscr, state)
    _refresh(stdscr)

# ── TAB 4: GRAPH — area chart, adaptive Y scale ────────────────────────────
# Area fill from bottom up. Metrics drawn lowest→highest priority (CPU on top).
def _gpu_color(gpu):
    # AMD=red, NVIDIA/unknown=light-green (distinct from CPU blue)
    src   = gpu.get('source', '')
    model = gpu.get('model', '').lower()
    if src in ('hwmon', 'rocm') or 'amd' in model or 'radeon' in model:
        return C_WARN  # red
    return C_NET  # light-green for nvidia/unknown

# ── TAB 3: HEX — process memory inspector ────────────────────────────────

def read_maps(pid):
    # parse /proc/pid/maps → list of {start, end, perms, name}
    regions = []
    try:
        for l in open(f'/proc/{pid}/maps', errors='replace'):
            parts = l.split()
            if len(parts) < 5: continue
            try:
                start_s, end_s = parts[0].split('-')
                regions.append({
                    'start': int(start_s, 16),
                    'end':   int(end_s,   16),
                    'perms': parts[1],
                    'name':  parts[5] if len(parts) > 5 else '',
                })
            except: pass
    except: pass
    return regions

def read_mem_hex(pid, addr, n_bytes):
    # read n_bytes from /proc/pid/mem at addr — requires root
    try:
        fd   = os.open(f'/proc/{pid}/mem', os.O_RDONLY)
        data = os.pread(fd, n_bytes, addr)
        os.close(fd)
        return data
    except:
        return None

# ── HEX sources: net capture + disk raw read ──────────────────────────────
_net_cap_buf  = {}   # iface → bytearray (capped at 128KB)
_net_cap_run  = {}   # iface → bool
_net_cap_lock = threading.Lock()

def _net_cap_worker(iface):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        s.settimeout(0.05)
        try: s.bind((iface, 0))
        except: pass
        while _net_cap_run.get(iface):
            try:
                pkt = s.recv(65535)
                with _net_cap_lock:
                    buf = _net_cap_buf.setdefault(iface, bytearray())
                    buf.extend(pkt)
                    if len(buf) > 131072:
                        del buf[:len(buf) - 131072]
            except socket.timeout: pass
        s.close()
    except: pass

def _net_cap_start(iface):
    if not iface or _net_cap_run.get(iface): return
    _net_cap_run[iface] = True
    threading.Thread(target=_net_cap_worker, args=(iface,), daemon=True).start()

def _net_cap_stop(iface):
    _net_cap_run[iface] = False

def _disk_raw_read(dev, offset, length):
    # read raw bytes from block device — needs read access to /dev/DEV
    try:
        fd = os.open(f'/dev/{dev}', os.O_RDONLY | os.O_NONBLOCK)
        data = os.pread(fd, length, offset)
        os.close(fd)
        return bytes(data)
    except: return b''

def _hex_bpr(dump_w):
    # max bytes per row that fit in dump_w, rounded to multiple of 8
    # layout: addr(12) + N*'XX '(3N) + ascii(N) = 12 + 4N <= dump_w
    n = max(8, ((dump_w - 12) // 4) // 8 * 8)
    return n

def _hex_render(stdscr, data, base_addr, match_offsets, hex_scroll,
                px, rows_avail, dump_w, H):
    # fill entire dump_w with hex — addr(12) + as many 'XX ' as fit + ascii tail
    N  = _hex_bpr(dump_w)
    gc = curses.color_pair(C_DISK)
    dc = curses.color_pair(C_USB) | curses.A_DIM
    sc = curses.color_pair(C_SEL) | curses.A_BOLD
    ac = curses.color_pair(C_USB) | curses.A_DIM
    for ri in range(rows_avail):
        sr = 2 + ri
        if sr > H - 3: break
        i     = (hex_scroll + ri) * N
        chunk = data[i:i+N]
        if not chunk: break
        put(stdscr, sr, px, f"{base_addr+i:010x}: ", dc)
        cx = px + 12
        for bi, b in enumerate(chunk):
            off = i + bi
            bcp = sc if off in match_offsets else (dc if b == 0 else gc)
            put(stdscr, sr, cx, f"{b:02x}", bcp)
            cx += 3
        asc_s = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        if cx < px + dump_w:
            put(stdscr, sr, cx, asc_s[:px + dump_w - cx], ac)

def draw_hex(stdscr, state):
    stdscr.erase()
    H, W = stdscr.getmaxyx()

    src        = state.get('hex_source', 'proc')
    hex_scroll = state.get('hex_scroll', 0)
    hex_srch   = state.get('hex_search', '')
    hex_sm     = state.get('hex_search_mode', False)
    src_lbl    = {'proc': 'MEM', 'disk': 'DISK', 'net': 'NET'}.get(src, src)

    hdr = f"─── HEX [{src_lbl}]  m=mem d=disk n=net  ←→=item ↑↓=scroll "
    hdr += "─" * max(0, W - len(hdr))
    put(stdscr, 0, 0, hdr[:W], curses.color_pair(C_HDR) | curses.A_BOLD)

    reg_w  = min(38, max(22, W // 4))
    sep_x  = reg_w
    dump_w = W - reg_w - 1
    data_h = H - 3   # rows 1..H-3

    rows_avail = max(1, H - 4)
    px         = sep_x + 1   # right pane x start

    if src == 'proc':
        hex_pid    = state.get('hex_pid', None)
        hex_region = state.get('hex_region', 0)
        hex_rs     = state.get('hex_reg_scroll', 0)
        regions    = read_maps(hex_pid) if hex_pid else []
        if hex_region >= len(regions) and regions:
            state['hex_region'] = 0; hex_region = 0

        hex_rs = max(0, min(hex_rs, max(0, len(regions) - data_h + 1)))
        if hex_region < hex_rs: hex_rs = hex_region
        elif hex_region >= hex_rs + data_h: hex_rs = hex_region - data_h + 1
        state['hex_reg_scroll'] = hex_rs

        for ri in range(data_h):
            sr = 1 + ri; abs_ri = hex_rs + ri
            if sr > H - 3: break
            put(stdscr, sr, sep_x, '│', curses.color_pair(C_HDR) | curses.A_DIM)
            if abs_ri >= len(regions): continue
            r    = regions[abs_ri]
            line = f"[{abs_ri}]{r['start']:08x}-{r['end']:08x} {r['perms']:<4} {fb(r['end']-r['start'])}"
            attr = curses.color_pair(C_SEL) | curses.A_BOLD if abs_ri == hex_region else 0
            put(stdscr, sr, 0, line[:reg_w], attr)

        if not hex_pid:
            put(stdscr, 2, px, "No PID — press p"[:dump_w], curses.color_pair(C_USB))
        elif not regions:
            put(stdscr, 2, px, f"No maps for PID {hex_pid}"[:dump_w], curses.color_pair(C_WARN))
        elif hex_region < len(regions):
            pr        = regions[hex_region]
            bpr       = _hex_bpr(dump_w)
            base_addr = pr['start'] + hex_scroll * bpr
            if base_addr >= pr['end']:
                max_sc = max(0, (pr['end'] - pr['start']) // bpr - rows_avail)
                state['hex_scroll'] = max_sc; hex_scroll = max_sc
                base_addr = pr['start'] + hex_scroll * bpr
            total = min(rows_avail * bpr, pr['end'] - base_addr)
            data  = read_mem_hex(hex_pid, base_addr, total)
            nm    = (pr['name'].split('/')[-1] if pr['name'] else '')[:20]
            lbl   = f"[{hex_region}]{pr['start']:010x}-{pr['end']:010x} {pr['perms']} {fb(pr['end']-pr['start'])} {nm}"
            put(stdscr, 1, px, lbl[:dump_w], curses.color_pair(C_SEL))
            if not data:
                put(stdscr, 2, px, "EPERM — need root"[:dump_w], curses.color_pair(C_WARN))
            else:
                match_offsets = set()
                if hex_srch:
                    try:
                        sb = bytes(int(x,16) for x in hex_srch.split())
                        pos = 0
                        while pos < len(data):
                            idx = data.find(sb, pos)
                            if idx == -1: break
                            for k in range(len(sb)): match_offsets.add(idx+k)
                            pos = idx + 1
                    except: pass
                _hex_render(stdscr, data, base_addr, match_offsets, 0, px, rows_avail, dump_w, H)

    elif src == 'disk':
        all_disks = state.get('disk', []) + state.get('removable', [])
        hex_sel   = max(0, min(state.get('hex_sel', 0), max(0, len(all_disks)-1)))
        state['hex_sel'] = hex_sel
        for ri in range(data_h):
            sr = 1 + ri
            if sr > H - 3: break
            put(stdscr, sr, sep_x, '│', curses.color_pair(C_HDR) | curses.A_DIM)
            if ri >= len(all_disks): continue
            d    = all_disks[ri]
            rot  = d.get('rotational')
            kind = 'OPT' if d.get('is_optical') else ('HDD' if rot else 'SSD')
            line = f"{'>' if ri==hex_sel else ' '}{d['dev']:<8} {kind} {fb(d.get('size_b',0))}"
            attr = curses.color_pair(C_SEL) | curses.A_BOLD if ri == hex_sel else curses.color_pair(C_DISK)
            put(stdscr, sr, 0, line[:reg_w], attr)
        if all_disks:
            dev       = all_disks[hex_sel]['dev']
            bpr       = _hex_bpr(dump_w)
            base_addr = hex_scroll * bpr
            data      = _disk_raw_read(dev, base_addr, rows_avail * bpr)
            put(stdscr, 1, px, f"  /dev/{dev}  offset:{base_addr:#x}"[:dump_w], curses.color_pair(C_SEL))
            if not data:
                put(stdscr, 2, px, f"Cannot read /dev/{dev} — need root"[:dump_w], curses.color_pair(C_WARN))
            else:
                _hex_render(stdscr, data, base_addr, set(), 0, px, rows_avail, dump_w, H)
        else:
            put(stdscr, 2, px, "No disks"[:dump_w], curses.color_pair(C_USB))

    elif src == 'net':
        nets   = state.get('net', [])
        ifaces = [n['iface'] for n in nets if n['iface'] != 'lo']
        hex_sel = max(0, min(state.get('hex_sel', 0), max(0, len(ifaces)-1)))
        state['hex_sel'] = hex_sel
        if ifaces:
            _net_cap_start(ifaces[hex_sel])
        for ri in range(data_h):
            sr = 1 + ri
            if sr > H - 3: break
            put(stdscr, sr, sep_x, '│', curses.color_pair(C_HDR) | curses.A_DIM)
            if ri >= len(ifaces): continue
            iface = ifaces[ri]
            with _net_cap_lock:
                blen = len(_net_cap_buf.get(iface, b''))
            active = _net_cap_run.get(iface, False)
            line = f"{'>' if ri==hex_sel else ' '}{iface:<12} {fb(blen):>7} {'●' if active else '○'}"
            attr = curses.color_pair(C_SEL) | curses.A_BOLD if ri == hex_sel else curses.color_pair(C_NET)
            put(stdscr, sr, 0, line[:reg_w], attr)
        if ifaces:
            iface    = ifaces[hex_sel]
            net_lock = state.get('net_lock', True)
            with _net_cap_lock:
                raw = bytes(_net_cap_buf.get(iface, b''))
            bpr    = _hex_bpr(dump_w)
            max_sc = max(0, len(raw) // bpr - rows_avail)
            if net_lock:
                # auto-tail: pin to end of buffer every frame
                state['hex_scroll'] = max_sc; hex_scroll = max_sc
            else:
                hex_scroll = min(hex_scroll, max_sc)
                state['hex_scroll'] = hex_scroll
            base_addr = hex_scroll * bpr
            data      = raw[base_addr:base_addr + rows_avail * bpr]
            lock_s    = '●LOCK' if net_lock else '○free'
            put(stdscr, 1, px,
                f"  {iface}  captured:{fb(len(raw))}  offset:{base_addr:#x}  l={lock_s}"[:dump_w],
                curses.color_pair(C_SEL))
            if not data:
                put(stdscr, 2, px, f"Capturing on {iface}... waiting for packets"[:dump_w],
                    curses.color_pair(C_USB))
            else:
                _hex_render(stdscr, data, base_addr, set(), 0, px, rows_avail, dump_w, H)
        else:
            put(stdscr, 2, px, "No interfaces"[:dump_w], curses.color_pair(C_USB))

    # ── hints H-2 ─────────────────────────────────────────────────────────
    srch_row = H - 2
    if hex_sm:
        put(stdscr, srch_row, 0, f"/hex: {hex_srch}_"[:W], curses.color_pair(C_SEL))
    elif hex_srch:
        put(stdscr, srch_row, 0, f"/hex: {hex_srch}"[:W], curses.color_pair(C_USB) | curses.A_DIM)
    else:
        lx = 0
        for cp, lbl in [(C_USB,'null'),(C_DISK,'data'),(C_SEL,'match')]:
            seg = f"█{lbl} "
            if lx + len(seg) >= W: break
            put(stdscr, srch_row, lx,   '█', curses.color_pair(cp))
            put(stdscr, srch_row, lx+1, f"{lbl} ", curses.color_pair(C_USB) | curses.A_DIM)
            lx += len(seg)
        if src == 'proc':
            hints = " p=PID /=search h=heap s=stack t=text"
        elif src == 'net':
            net_lock = state.get('net_lock', True)
            lock_clr = curses.color_pair(C_WARN) if net_lock else curses.color_pair(C_USB) | curses.A_DIM
            lock_s   = ' ●LOCK' if net_lock else ' ○free'
            put(stdscr, srch_row, lx, lock_s, lock_clr)
            lx += len(lock_s)
            hints = '  l=toggle'
        else:
            hints = ''
        put(stdscr, srch_row, lx, hints[:max(0, W-lx)], curses.color_pair(C_USB) | curses.A_DIM)
    put(stdscr, srch_row, sep_x, '│', curses.color_pair(C_HDR) | curses.A_DIM)

    draw_rec_indicator(stdscr, H, W, state)
    draw_statusbar(stdscr, state)
    _refresh(stdscr)

# ── collect ────────────────────────────────────────────────────────────────

def collect(state):
    global _rapl_prev
    cores, load, rapl_raw = read_cpu()
    now = time.time(); rapl_w = 0.0
    if rapl_raw and _rapl_prev[0]:
        dt     = max(0.001, now - _rapl_prev[1])
        rapl_w = (rapl_raw - _rapl_prev[0]) / dt / 1e6
    _rapl_prev = (rapl_raw, now)
    nets, bt          = read_net()
    mem               = read_mem()
    gpu               = read_gpu()
    disk_int, disk_rm = read_disk()

    return {
        'cpu':         (cores, load, rapl_raw),
        'rapl_w':      max(0, rapl_w),
        'mem':         mem,
        'gpu':         gpu,
        'disk':        disk_int,
        'removable':   disk_rm,
        'net':         nets,
        'bt':          bt,
        'usb':         read_usb(),
        'audio':        read_audio(),
        'audio_detail': read_audio_detail(),
        'hooks':        read_hooks(),
        'battery':      read_battery(),
        'uptime_s':     read_uptime(),
        'vms':          read_vms(),
        'procs':        read_procs(state.get('sort','cpu'),
                                   state.get('filt','user'),
                                   state.get('search','')),
        'proc_counts':  read_proc_counts(),
    }

# ── recording ─────────────────────────────────────────────────────────────

def record_snapshot(state, f):
    # one TSV-ish line per collect() cycle — human-readable + grepable
    cores, load, _ = state.get('cpu', ([], (0,0,0), 0))
    avg_cpu = sum(c['pct'] for c in cores) / len(cores) if cores else 0.0
    max_f   = max((c['freq'] for c in cores), default=0)
    max_t   = max((c['temp'] for c in cores), default=0)
    mem     = state.get('mem', {})
    gpu     = state.get('gpu', {})
    rapl_w  = state.get('rapl_w', 0.0)
    disks   = state.get('disk', [])
    nets    = state.get('net', [])
    mem_pct = pct2(mem.get('used',0), mem.get('total',1))
    disk_s  = ' '.join(f"{d['dev']}:{fb(d['rd'])}/{fb(d['wr'])}" for d in disks[:2]) or '--'
    net_s   = ' '.join(f"{n['iface']}:{fb(n['rx'])}/{fb(n['tx'])}" for n in nets[:2]) or '--'
    ts      = time.strftime('%Y-%m-%d %H:%M:%S')
    line    = (f"{ts} | CPU:{avg_cpu:.0f}% {max_f}MHz {max_t}C load:{load[0]:.1f}/{load[1]:.1f}/{load[2]:.1f}"
               f" | RAM:{fmt_mem(mem.get('used',0))}/{fmt_mem(mem.get('total',1))} {mem_pct}%"
               f" swap:{fmt_mem(mem.get('swap_used',0))}"
               f" | GPU:{gpu.get('util',0)}% {gpu.get('temp',0)}C"
               f" {fmt_mem(gpu.get('mem_used',0)*1024)}/{fmt_mem(gpu.get('mem_tot',0)*1024)}"
               f" {gpu.get('power',0):.0f}W"
               f" | PWR:{rapl_w:.0f}W | {disk_s} | {net_s}\n")
    f.write(line)
    f.flush()

def run_headless(args):
    # headless --record mode: collect in loop, write to file/stdout, no curses
    rec_dir = os.path.expanduser('~/.local/share/bsc')
    if args.out and args.out != '-':
        os.makedirs(os.path.dirname(os.path.abspath(args.out)) or rec_dir, exist_ok=True)
        f = open(args.out, 'w')
    else:
        f = os.fdopen(os.dup(sys.stdout.fileno()), 'w')
    f.write(f"# bsc record — started {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write("# format: timestamp | CPU avg%/MHz/C | RAM used/total | GPU util/C/VRAM/W | PWR W | DISK rd/wr | NET rx/tx\n")
    f.flush()
    state      = {'sort': 'cpu', 'filt': 'user', 'search': ''}
    start      = time.time()
    interval_s = args.interval / 1000.0
    try:
        while True:
            data = collect(state)
            state.update(data)
            record_snapshot(state, f)
            if args.duration > 0 and time.time() - start >= args.duration:
                break
            time.sleep(interval_s)
    except KeyboardInterrupt:
        pass
    finally:
        f.close()

# ── input: PID picker for DEV strace section ──────────────────────────────

def _clipboard(text):
    for cmd in (['xclip', '-selection', 'clipboard'],
                ['xsel', '-bi'],
                ['wl-copy']):
        try:
            subprocess.Popen(cmd, stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                             ).communicate(text.encode())
            return True
        except FileNotFoundError:
            continue
    return False

def handle_pid_input(stdscr, state):
    # arrow-key process picker; type to filter by name/pid, ↑↓ navigate, Enter=pick, Esc=cancel
    H, W = stdscr.getmaxyx()
    procs = []
    try:
        for d in os.scandir('/proc'):
            if d.name.isdigit():
                try:
                    comm = open(f'/proc/{d.name}/comm').read().strip()
                    procs.append((int(d.name), comm))
                except: pass
    except: pass
    procs.sort(key=lambda x: x[0])

    sel = 0; scroll = 0; filt = ''
    list_h = min(H - 5, 18)
    curses.curs_set(0)

    while True:
        flt = [(pid, c) for pid, c in procs
               if filt in str(pid) or filt in c.lower()] if filt else procs
        sel = min(sel, max(0, len(flt) - 1))
        if sel < scroll: scroll = sel
        if sel >= scroll + list_h: scroll = sel - list_h + 1

        oy = max(0, H // 2 - list_h // 2 - 1)
        put(stdscr, oy, 0,
            (f" PID pick  filter:{filt or '*'}  ↑↓=nav  Enter=ok  Esc=cancel  Bksp=clear")[:W],
            curses.color_pair(C_SEL))
        for li in range(list_h):
            idx = scroll + li
            ry = oy + 1 + li
            if ry >= H - 1: break
            if idx < len(flt):
                pid, comm = flt[idx]
                clr = curses.color_pair(C_SEL) if idx == sel else curses.color_pair(C_DISK)
                mrk = '>' if idx == sel else ' '
                put(stdscr, ry, 0, f"{mrk}{pid:>7}  {comm}"[:W], clr)
            else:
                put(stdscr, ry, 0, ' ' * min(W, 32), 0)
        put(stdscr, oy + 1 + list_h, 0,
            f" {len(flt)} / {len(procs)} procs"[:W], curses.color_pair(C_USB))
        _refresh(stdscr)

        key = stdscr.getch()
        if key == 27:   break
        elif key == curses.KEY_UP:   sel = max(0, sel - 1)
        elif key == curses.KEY_DOWN: sel = min(len(flt) - 1, sel + 1) if flt else 0
        elif key in (curses.KEY_PPAGE,): sel = max(0, sel - list_h)
        elif key in (curses.KEY_NPAGE,): sel = min(len(flt) - 1, sel + list_h) if flt else 0
        elif key in (ord('\n'), curses.KEY_ENTER):
            if flt: state['sel_pid'] = flt[sel][0]
            break
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            filt = filt[:-1]; sel = 0; scroll = 0
        elif 32 <= key < 127:
            filt += chr(key); sel = 0; scroll = 0
    curses.curs_set(0)

# ── main ───────────────────────────────────────────────────────────────────

def main(stdscr):
    curses.start_color(); curses.use_default_colors(); curses.curs_set(0)
    stdscr.timeout(100)
    c256 = curses.COLORS >= 256
    # CPU=violet(93), GPU=cyan(51), RAM=yellow(220), ZRAM/PWR=magenta(141),
    # DISK=green(82), NET=light-green(118) — all distinct, no two same color
    theme = _load_theme() if c256 else {}
    _clr = lambda key, dflt256, dflt8: theme.get(key, dflt256) if c256 else dflt8
    curses.init_pair(C_HDR,  _clr('HDR',  208, curses.COLOR_RED),     -1)
    curses.init_pair(C_CPU,  _clr('CPU',  93,  curses.COLOR_MAGENTA), -1)
    curses.init_pair(C_GPU,  _clr('GPU',  82,  curses.COLOR_GREEN),   -1)
    curses.init_pair(C_RAM,  _clr('RAM',  220, curses.COLOR_YELLOW),  -1)
    curses.init_pair(C_ZRAM, _clr('ZRAM', 141, curses.COLOR_MAGENTA), -1)
    curses.init_pair(C_DISK, _clr('DISK', 82,  curses.COLOR_GREEN),   -1)
    curses.init_pair(C_NET,  _clr('NET',  33,  curses.COLOR_BLUE),    -1)
    curses.init_pair(C_SEL,  _clr('SEL',  226, curses.COLOR_YELLOW),  -1)
    curses.init_pair(C_USB,  _clr('USB',  245, curses.COLOR_WHITE),   -1)
    curses.init_pair(C_MARK, _clr('MARK', 214, curses.COLOR_YELLOW),  -1)
    curses.init_pair(C_WARN, _clr('WARN', 196, curses.COLOR_RED),     -1)

    state = {
        'tab':         0,          # 0=OVW+PRC 1=DEV 2=HEX
        'sel':         0,          # selected proc row in PROCS tab
        'scroll':      0,
        'sort':        'cpu',
        'filt':        'user',
        'marked':      set(),
        'input_mode':  False,
        'input_buf':   '',
        'search':      '',
        'search_mode': False,
        'interval_ms': 1000,       # refresh rate, +/- keys change it
        'view_pid':    None,       # PID shown in right-side detail panel (tab 0)
        'sel_pid':     None,       # PID watched in DEV details panel
        'core_trace':  0,          # CPU core shown in DEV syscall trace
        'dev_scroll':  0,
        'net_scroll':  0,
        'rec':         None,       # None or {f, path, start}
        'hex_source':     'proc',        # 'proc' | 'disk' | 'net'
        'hex_pid':        os.getpid(),  # PID for proc source
        'hex_scroll':     0,
        'hex_region':     0,
        'hex_reg_scroll': 0,
        'hex_sel':        0,            # selected item in disk/net left pane
        'hex_search':     '',
        'hex_search_mode':False,
        'net_lock':       True,         # net source: True=tail auto-scroll, False=manual
    }
    last_collect = 0.0
    last_draw    = 0.0
    dirty        = True

    while True:
        now      = time.time()
        interval = state['interval_ms'] / 1000.0
        if now - last_collect >= interval:
            data = collect(state)
            state.update(data)
            last_collect = now
            dirty = True
            if state['rec']:
                record_snapshot(state, state['rec']['f'])

        tab = state['tab']
        # cap redraws at 30fps to avoid tearing from held scroll keys
        # (data still collects at interval_ms, but display doesn't thrash)
        min_draw_dt = 0.033
        if dirty and now - last_draw >= min_draw_dt:
            if   tab == 0: draw_main(stdscr, state)
            elif tab == 1: draw_dev(stdscr, state)
            elif tab == 2: draw_hex(stdscr, state)
            dirty = False
            last_draw = now

        stdscr.timeout(16 if tab == 2 else 33 if tab == 1 else 100)
        key   = stdscr.getch()
        H, W  = stdscr.getmaxyx()
        tab   = state['tab']
        if key != -1:
            dirty = True
        procs = state.get('procs', [])

        # ── search mode (PROCS tab) ───────────────────────────────────────
        if state['search_mode']:
            if key == 27 or key == ord('q'):
                state['search'] = ''; state['search_mode'] = False; curses.curs_set(0)
                if key == ord('q'):
                    if state['rec']: state['rec']['f'].close()
                    break
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                state['search'] = state['search'][:-1]
            elif key in (ord('\n'), curses.KEY_ENTER):
                state['search_mode'] = False; curses.curs_set(0)
            elif 32 <= key < 127:
                state['search'] += chr(key)
                state['sel'] = 0; state['scroll'] = 0
            continue

        # ── input mode (PROCS tab :cmd) ───────────────────────────────────
        if state['input_mode']:
            if key == 27:
                state['input_mode'] = False; state['input_buf'] = ''; curses.curs_set(0)
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                state['input_buf'] = state['input_buf'][:-1]
            elif key in (ord('\n'), curses.KEY_ENTER):
                cmd   = state['input_buf'].strip()
                sel_p = procs[state['sel']] if procs and state['sel'] < len(procs) else None
                pid   = sel_p['pid'] if sel_p else ''
                if cmd:
                    try:
                        subprocess.Popen(['/bin/bash', '-c', f'{cmd} {pid}'],
                                         start_new_session=True)
                    except: pass
                state['input_mode'] = False; state['input_buf'] = ''; curses.curs_set(0)
            elif 32 <= key < 127:
                state['input_buf'] += chr(key)
            continue

        # ── global keys — work in any tab ─────────────────────────────────
        if key == ord('q'):
            if state['rec']: state['rec']['f'].close()
            break
        elif key == 9:  # Tab → next tab
            state['tab'] = (state['tab'] + 1) % 3
        elif key == curses.KEY_BTAB:  # Shift+Tab → prev tab
            state['tab'] = (state['tab'] - 1) % 3
        elif key == ord('1'): state['tab'] = 0
        elif key == ord('2'): state['tab'] = 1
        elif key == ord('3'): state['tab'] = 2
        elif key == ord('+') or key == ord('='):
            state['interval_ms'] = min(9999, state['interval_ms'] + 100)
        elif key == ord('-'):
            state['interval_ms'] = max(100,  state['interval_ms'] - 100)
        elif key == ord('R'):
            if state['rec'] is None:
                rec_dir = os.path.expanduser('~/.local/share/bsc')
                os.makedirs(rec_dir, exist_ok=True)
                ts_s = time.strftime('%Y-%m-%d_%H-%M-%S')
                path = os.path.join(rec_dir, f'bsc-{ts_s}.txt')
                f    = open(path, 'w')
                f.write(f"# bsc record — started {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("# format: timestamp | CPU avg%/MHz/C | RAM | GPU | PWR | DISK | NET\n")
                f.flush()
                state['rec'] = {'f': f, 'path': path, 'start': time.time()}
            else:
                state['rec']['f'].close()
                state['rec'] = None

        # ── tab-specific keys ─────────────────────────────────────────────
        elif tab == 0:  # OVW+PRC
            top_h_k = max(10, min(H // 2, 22))
            avail = max(1, H - (top_h_k + 2) - 3)
            if key in (curses.KEY_DOWN, ord('J'), curses.KEY_SF):
                step = 1 if key == curses.KEY_DOWN else 5
                state['sel'] = min(state['sel']+step, max(0, len(procs)-1))
                if state['sel'] >= state['scroll'] + avail:
                    state['scroll'] = state['sel'] - avail + 1
            elif key in (curses.KEY_UP, ord('K'), curses.KEY_SR):
                step = 1 if key == curses.KEY_UP else 5
                state['sel'] = max(state['sel']-step, 0)
                if state['sel'] < state['scroll']:
                    state['scroll'] = state['sel']
            elif key == curses.KEY_LEFT:
                fi = FILTER_MODES.index(state['filt'])
                state['filt'] = FILTER_MODES[(fi-1) % len(FILTER_MODES)]
                state['sel'] = 0; state['scroll'] = 0
            elif key == curses.KEY_RIGHT:
                fi = FILTER_MODES.index(state['filt'])
                state['filt'] = FILTER_MODES[(fi+1) % len(FILTER_MODES)]
                state['sel'] = 0; state['scroll'] = 0
            elif key == ord('c'): state['sort'] = 'cpu';    state['sel'] = 0; state['scroll'] = 0
            elif key == ord('m'): state['sort'] = 'mem_kb'; state['sel'] = 0; state['scroll'] = 0
            elif key == ord(' '):
                if procs and state['sel'] < len(procs):
                    pid = procs[state['sel']]['pid']
                    if pid in state['marked']: state['marked'].discard(pid)
                    else: state['marked'].add(pid)
            elif key == ord('k') and procs and state['sel'] < len(procs):
                try: os.kill(int(procs[state['sel']]['pid']), 15)
                except: pass
            elif key == ord('9') and procs and state['sel'] < len(procs):
                try: os.kill(int(procs[state['sel']]['pid']), 9)
                except: pass
            elif key == ord(':'):
                state['input_mode'] = True; state['input_buf'] = ''; curses.curs_set(1)
            elif key == ord('/'):
                state['search_mode'] = True; curses.curs_set(1)
            elif key == ord('y') and procs and state['sel'] < len(procs):
                _clipboard(str(procs[state['sel']]['pid']))
            elif key == ord('Y') and procs and state['sel'] < len(procs):
                p = procs[state['sel']]
                _clipboard(p.get('cmd') or p.get('name',''))
            elif key in (ord('\n'), curses.KEY_ENTER, ord('v')) and procs and state['sel'] < len(procs):
                # toggle right-side detail panel for selected proc
                pid = procs[state['sel']]['pid']
                state['view_pid'] = None if state.get('view_pid') == pid else pid
            elif key == ord('d') and procs and state['sel'] < len(procs):
                # d=dtrace: jump to DEV tab (core trace runs there)
                state['sel_pid'] = int(procs[state['sel']]['pid'])
                state['tab'] = 1
            elif key == 27:  # Esc — close panel
                state['view_pid'] = None
            elif key == ord('i'):  # scroll net column up
                state['net_scroll'] = max(0, state.get('net_scroll', 0) - 1)
            elif key == ord('o'):  # scroll net column down
                nets_n = len(state.get('net', []))
                state['net_scroll'] = min(state.get('net_scroll', 0) + 1, max(0, nets_n - 1))

        elif tab == 1:  # DEV
            n_cores = len(state.get('cpu', ([],))[0]) or 1
            if key in (curses.KEY_LEFT, ord('h')):
                state['core_trace'] = max(0, state.get('core_trace', 0) - 1)
                state['dev_scroll'] = 0
            elif key in (curses.KEY_RIGHT, ord('l')):
                state['core_trace'] = min(n_cores - 1, state.get('core_trace', 0) + 1)
                state['dev_scroll'] = 0
            elif key in (ord('i'), curses.KEY_UP, ord('K'), curses.KEY_SR):
                step = 1 if key in (ord('i'), curses.KEY_UP) else 5
                state['dev_scroll'] = max(0, state.get('dev_scroll', 0) - step)
            elif key in (ord('o'), curses.KEY_DOWN, ord('J'), curses.KEY_SF):
                step = 1 if key in (ord('o'), curses.KEY_DOWN) else 5
                state['dev_scroll'] = state.get('dev_scroll', 0) + step

        elif tab == 2:  # HEX
            src = state.get('hex_source', 'proc')
            if state.get('hex_search_mode'):
                if key == 27:
                    state['hex_search_mode'] = False; curses.curs_set(0)
                elif key in (curses.KEY_BACKSPACE, 127, 8):
                    state['hex_search'] = state['hex_search'][:-1]
                elif key in (ord('\n'), curses.KEY_ENTER):
                    state['hex_search_mode'] = False; curses.curs_set(0)
                elif 32 <= key < 127:
                    state['hex_search'] += chr(key)
            elif key == ord('m'):
                state['hex_source'] = 'proc'; state['hex_scroll'] = 0
            elif key == ord('d'):
                state['hex_source'] = 'disk'; state['hex_scroll'] = 0; state['hex_sel'] = 0
            elif key == ord('n'):
                state['hex_source'] = 'net';  state['hex_scroll'] = 0; state['hex_sel'] = 0
            elif key == ord('p') and src == 'proc':
                handle_pid_input(stdscr, state)
                if state.get('sel_pid'):
                    state['hex_pid']    = state['sel_pid']
                    state['hex_scroll'] = 0; state['hex_region'] = 0
            elif key == ord('/'):
                state['hex_search'] = ''; state['hex_search_mode'] = True; curses.curs_set(1)
            elif key == ord('l') and src == 'net':
                state['net_lock'] = not state.get('net_lock', True)
            elif key in (curses.KEY_DOWN, ord('J'), curses.KEY_SF):
                if src == 'net': state['net_lock'] = False
                state['hex_scroll'] += 1 if key == curses.KEY_DOWN else 5
            elif key in (curses.KEY_UP, ord('K'), curses.KEY_SR):
                if src == 'net': state['net_lock'] = False
                state['hex_scroll'] = max(0, state['hex_scroll'] - (1 if key == curses.KEY_UP else 5))
            elif key == curses.KEY_NPAGE:
                if src == 'net': state['net_lock'] = False
                state['hex_scroll'] += H - 4
            elif key == curses.KEY_PPAGE:
                if src == 'net': state['net_lock'] = False
                state['hex_scroll'] = max(0, state['hex_scroll'] - (H - 4))
            elif key == curses.KEY_RIGHT:
                if src == 'proc':
                    regions = read_maps(state.get('hex_pid')) if state.get('hex_pid') else []
                    state['hex_region'] = min(state['hex_region']+1, max(0, len(regions)-1))
                else:
                    state['hex_sel'] = state.get('hex_sel', 0) + 1
                state['hex_scroll'] = 0
            elif key == curses.KEY_LEFT:
                if src == 'proc':
                    state['hex_region'] = max(state['hex_region']-1, 0)
                else:
                    state['hex_sel'] = max(0, state.get('hex_sel', 0) - 1)
                state['hex_scroll'] = 0
            elif src == 'proc':  # proc-only shortcuts
                regions = read_maps(state.get('hex_pid')) if state.get('hex_pid') else []
                if key == ord('h'):
                    for ri, r in enumerate(regions):
                        if '[heap]' in r.get('name',''):
                            state['hex_region'] = ri; state['hex_scroll'] = 0; break
                elif key == ord('s'):
                    for ri, r in enumerate(regions):
                        if '[stack]' in r.get('name',''):
                            state['hex_region'] = ri; state['hex_scroll'] = 999999; break
                elif key == ord('t'):
                    for ri, r in enumerate(regions):
                        if r.get('perms','')[2] == 'x':
                            state['hex_region'] = ri; state['hex_scroll'] = 0; break

        # other tabs have no special keys beyond global ones

def cli():
    p = argparse.ArgumentParser(description='bsc — system monitor')
    p.add_argument('--record',   action='store_true', help='headless record mode')
    p.add_argument('--out',      default=None,        help='output file (default: stdout)')
    p.add_argument('--duration', type=int, default=0, help='record duration seconds (0=infinite)')
    p.add_argument('--interval', type=int, default=1000, help='interval ms')
    args = p.parse_args()
    if args.record:
        run_headless(args)
    else:
        curses.wrapper(main)

cli()
