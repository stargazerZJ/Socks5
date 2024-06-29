package Socks5

import (
	"time"

	"github.com/puzpuzpuz/xsync/v3"
)

type TimedValue[T any] struct {
	Value     T
	Timestamp time.Time
}

type TimedMap[T any] struct {
	data *xsync.MapOf[string, TimedValue[T]]
}

func NewTimedMap[T any]() *TimedMap[T] {
	tm := &TimedMap[T]{
		data: xsync.NewMapOf[string, TimedValue[T]](),
	}
	go tm.cleanerThread()
	return tm
}

func (tm *TimedMap[T]) Set(key string, value T) {
	tm.data.Store(key, TimedValue[T]{Value: value, Timestamp: time.Now()})
}

func (tm *TimedMap[T]) Get(key string) (T, bool) {
	if timedValue, exists := tm.data.Load(key); exists {
		tm.data.Store(key, TimedValue[T]{Value: timedValue.Value, Timestamp: time.Now()})
		return timedValue.Value, true
	}
	var zero T
	return zero, false
}

func (tm *TimedMap[T]) cleanerThread() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		tm.cleanExpired()
	}
}

func (tm *TimedMap[T]) cleanExpired() {
	now := time.Now()
	tm.data.Range(func(key string, timedValue TimedValue[T]) bool {
		if now.Sub(timedValue.Timestamp) > 300*time.Second {
			tm.data.Delete(key)
		}
		return true
	})
}
