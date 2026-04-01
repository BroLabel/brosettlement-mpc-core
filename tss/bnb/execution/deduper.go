package execution

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
)

const dedupPruneEvery = 128

type inboundDeduper interface {
	ShouldAccept(frame protocol.Frame) (bool, error)
}

type deduperConfig struct {
	TTL           time.Duration
	MaxEntries    int
	MaxFrameBytes int
}

type ttlFrameDeduper struct {
	seen         map[string]int64
	insertions   uint64
	ttlNanos     int64
	maxEntries   int
	maxFrameSize int
}

func newTTLFrameDeduper(cfg deduperConfig) *ttlFrameDeduper {
	return &ttlFrameDeduper{
		seen:         make(map[string]int64),
		ttlNanos:     cfg.TTL.Nanoseconds(),
		maxEntries:   cfg.MaxEntries,
		maxFrameSize: cfg.MaxFrameBytes,
	}
}

func (d *ttlFrameDeduper) ShouldAccept(frame protocol.Frame) (bool, error) {
	if len(frame.Payload) > d.maxFrameSize {
		return false, fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(frame.Payload), d.maxFrameSize)
	}
	nowNanos := time.Now().UnixNano()
	if d.insertions%dedupPruneEvery == 0 {
		expireBefore := nowNanos - d.ttlNanos
		for k, tsNanos := range d.seen {
			if tsNanos < expireBefore {
				delete(d.seen, k)
			}
		}
	}
	if len(d.seen) >= d.maxEntries {
		var oldestKey string
		var oldestTS int64
		for k, tsNanos := range d.seen {
			if oldestKey == "" || tsNanos < oldestTS {
				oldestKey = k
				oldestTS = tsNanos
			}
		}
		if oldestKey != "" {
			delete(d.seen, oldestKey)
		}
	}
	key := frameDedupKey(frame)
	if _, exists := d.seen[key]; exists {
		return false, ErrDuplicateFrame
	}
	d.seen[key] = nowNanos
	d.insertions++
	return true, nil
}

func frameDedupKey(frame protocol.Frame) string {
	hash := frame.PayloadHash
	if hash == "" {
		hash = shortHash(frame.Payload)
	}
	return strings.Join([]string{
		frame.SessionID,
		frame.Stage,
		frame.FromParty,
		strconv.FormatUint(frame.Seq, 10),
		hash,
	}, "|")
}

func isDuplicateErr(err error) bool {
	return errors.Is(err, ErrDuplicateFrame)
}
