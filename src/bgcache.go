package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// spinTick increments each render frame — used for animated spinner
var spinTick atomic.Uint32

func spinChar() string {
	return string([]rune(`-\|/`)[spinTick.Load()%4])
}

// bgVal — generic background-refreshed cached value.
// fetch() is called in a goroutine; zero value returned until first result.
type bgVal[T any] struct {
	mu      sync.Mutex
	val     T
	loading bool
	loaded  time.Time
	ttl     time.Duration
}

func (b *bgVal[T]) get(fetch func() T) (T, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.loading {
		return b.val, true // still loading
	}
	if !b.loaded.IsZero() && time.Since(b.loaded) < b.ttl {
		return b.val, false // fresh
	}
	b.loading = true
	go func() {
		v := fetch()
		b.mu.Lock()
		b.val = v
		b.loading = false
		b.loaded = time.Now()
		b.mu.Unlock()
	}()
	return b.val, b.loading
}

// ── SEC background caches ────────────────────────────────────────────────────

type iptResult struct{ chains, rules int }
type nftResult struct{ rules int }

var (
	bgPending  = &bgVal[int]{ttl: 5 * time.Minute}
	bgSUIDs    = &bgVal[int]{ttl: 2 * time.Minute}
	bgIPT      = &bgVal[iptResult]{ttl: 15 * time.Second}
	bgNFT      = &bgVal[nftResult]{ttl: 15 * time.Second}
	bgLastLogin = &bgVal[string]{ttl: 30 * time.Second}
	bgCaps     = &bgVal[[]string]{ttl: 10 * time.Second}
	bgWWDirs   = &bgVal[[]string]{ttl: 30 * time.Second}
)

func bgGetPending() (int, bool) {
	return bgPending.get(checkPendingSecUpdates)
}

func bgGetSUIDs() (int, bool) {
	return bgSUIDs.get(scanSUIDBins)
}

func bgGetIPT() (iptResult, bool) {
	return bgIPT.get(func() iptResult {
		c, r := countIPTablesRules()
		return iptResult{c, r}
	})
}

func bgGetNFT() (nftResult, bool) {
	return bgNFT.get(func() nftResult {
		return nftResult{countNFTRules()}
	})
}

func bgGetLastLogin() (string, bool) {
	return bgLastLogin.get(checkLastLogin)
}

func bgGetCaps() ([]string, bool) {
	return bgGetCapsInner()
}

func bgGetCapsInner() ([]string, bool) {
	return bgCaps.get(checkDangerousCaps)
}

func bgGetWWDirs() ([]string, bool) {
	return bgWWDirs.get(checkWorldWritableDirs)
}

func anyBgLoading() bool {
	for _, check := range []func() bool{
		func() bool { bgPending.mu.Lock(); v := bgPending.loading; bgPending.mu.Unlock(); return v },
		func() bool { bgSUIDs.mu.Lock(); v := bgSUIDs.loading; bgSUIDs.mu.Unlock(); return v },
		func() bool { bgIPT.mu.Lock(); v := bgIPT.loading; bgIPT.mu.Unlock(); return v },
		func() bool { bgNFT.mu.Lock(); v := bgNFT.loading; bgNFT.mu.Unlock(); return v },
		func() bool { bgLastLogin.mu.Lock(); v := bgLastLogin.loading; bgLastLogin.mu.Unlock(); return v },
		func() bool { bgCaps.mu.Lock(); v := bgCaps.loading; bgCaps.mu.Unlock(); return v },
		func() bool { bgWWDirs.mu.Lock(); v := bgWWDirs.loading; bgWWDirs.mu.Unlock(); return v },
		func() bool { asmMu.Lock(); v := asmCache.loading; asmMu.Unlock(); return v },
	} {
		if check() {
			return true
		}
	}
	return false
}
