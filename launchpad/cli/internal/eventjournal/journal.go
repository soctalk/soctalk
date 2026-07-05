// Package eventjournal is the per-run append-only event log: every
// orchestrator event gets a monotonic sequence number, is persisted to
// events.jsonl, and is fanned out to any number of live subscribers.
// Subscribe(sinceSeq) replays history first and then switches to live tail
// with no gap — the registration happens under the same lock as appends.
//
// Appends never block on slow subscribers: a subscriber whose channel is
// full has events dropped and a drop counter incremented (the WS layer can
// tell the client to re-sync from its last seq).
package eventjournal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/soctalk/launchpad/internal/orchestrator"
)

// SeqEvent wraps an orchestrator event with its journal sequence number.
type SeqEvent struct {
	Seq int64 `json:"seq"`
	orchestrator.Event
}

type subscriber struct {
	ch      chan SeqEvent
	dropped atomic.Int64
}

// Journal is one run's event log. Safe for concurrent use.
type Journal struct {
	mu      sync.Mutex
	f       *os.File
	events  []SeqEvent
	subs    map[int]*subscriber
	nextSub int
	closed  bool
}

// Open creates (or re-opens) the journal file at path, loading any existing
// events so a restarted server can serve full replays.
func Open(path string) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	j := &Journal{subs: map[int]*subscriber{}}
	if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
		sc := bufio.NewScanner(bytes.NewReader(b))
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			var ev SeqEvent
			if json.Unmarshal(sc.Bytes(), &ev) == nil {
				j.events = append(j.events, ev)
			}
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	j.f = f
	return j, nil
}

// Append assigns the next seq, persists, and broadcasts. Never blocks.
func (j *Journal) Append(ev orchestrator.Event) SeqEvent {
	j.mu.Lock()
	defer j.mu.Unlock()
	se := SeqEvent{Seq: int64(len(j.events)) + 1, Event: ev}
	j.events = append(j.events, se)
	if j.f != nil {
		if b, err := json.Marshal(se); err == nil {
			_, _ = j.f.Write(append(b, '\n'))
		}
	}
	for _, s := range j.subs {
		select {
		case s.ch <- se:
		default:
			s.dropped.Add(1)
		}
	}
	return se
}

// Snapshot returns all events with seq > sinceSeq.
func (j *Journal) Snapshot(sinceSeq int64) []SeqEvent {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.sliceAfterLocked(sinceSeq)
}

func (j *Journal) sliceAfterLocked(sinceSeq int64) []SeqEvent {
	if sinceSeq < 0 {
		sinceSeq = 0
	}
	if sinceSeq >= int64(len(j.events)) {
		return nil
	}
	out := make([]SeqEvent, len(j.events)-int(sinceSeq))
	copy(out, j.events[sinceSeq:])
	return out
}

// Subscribe returns a channel that first yields every event after sinceSeq
// then live events, plus a cancel func. The replay is buffered into the
// channel under the append lock, so no event can slip between replay and
// live registration.
func (j *Journal) Subscribe(sinceSeq int64) (<-chan SeqEvent, func()) {
	j.mu.Lock()
	replay := j.sliceAfterLocked(sinceSeq)
	ch := make(chan SeqEvent, len(replay)+512)
	for _, ev := range replay {
		ch <- ev
	}
	id := j.nextSub
	j.nextSub++
	sub := &subscriber{ch: ch}
	if !j.closed {
		j.subs[id] = sub
	} else {
		close(ch)
	}
	j.mu.Unlock()
	cancel := func() {
		j.mu.Lock()
		if s, ok := j.subs[id]; ok {
			delete(j.subs, id)
			close(s.ch)
		}
		j.mu.Unlock()
	}
	return ch, cancel
}

// LastSeq returns the newest sequence number (0 when empty).
func (j *Journal) LastSeq() int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return int64(len(j.events))
}

// Close flushes and closes the file and all subscriber channels.
func (j *Journal) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	j.closed = true
	for id, s := range j.subs {
		delete(j.subs, id)
		close(s.ch)
	}
	if j.f != nil {
		_ = j.f.Close()
		j.f = nil
	}
}
