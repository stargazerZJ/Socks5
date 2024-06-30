package Socks5

import (
	"time"

	"github.com/puzpuzpuz/xsync/v3"
)

type TimedMap[V any] struct {
	data  *xsync.MapOf[string, V]
	times *xsync.MapOf[string, time.Time]
}

func NewTimedMap[V any]() *TimedMap[V] {
	tm := &TimedMap[V]{
		data:  xsync.NewMapOf[string, V](),
		times: xsync.NewMapOf[string, time.Time](),
	}
	go tm.cleanerThread()
	return tm
}

func (tm *TimedMap[V]) Set(key string, value V) {
	tm.data.Store(key, value)
	tm.times.Store(key, time.Now())
}

func (tm *TimedMap[V]) Get(key string) (V, bool) {
	value, exists := tm.data.Load(key)
	if exists {
		tm.times.Store(key, time.Now()) // Reset timeout
	}
	return value, exists
}

func (tm *TimedMap[V]) cleanerThread() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		tm.cleanExpired()
	}
}

func (tm *TimedMap[V]) cleanExpired() {
	now := time.Now()
	tm.times.Range(func(key string, timestamp time.Time) bool {
		if now.Sub(timestamp) > 300*time.Second {
			tm.data.Delete(key)
			tm.times.Delete(key)
		}
		return true
	})
}
