package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

// Keepalive constants — battle-tested values borrowed from Semaphore UI.
const (
	wsWriteWait = 20 * time.Second
	wsPongWait  = 120 * time.Second
	wsPingEvery = 108 * time.Second
)

// handleWS streams a run's events: replay from ?since_seq=N, then live tail.
// The journal's Subscribe does the replay-then-live handoff atomically.
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	run, ok := s.Mgr.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "no such run")
		return
	}
	up := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 4096,
		// Token + origin were already checked by the middleware; here we
		// re-check origin only (the upgrader's default is stricter than ours
		// because it rejects the Vite dev origin).
		CheckOrigin: func(r *http.Request) bool { return s.originOK(r) },
	}
	conn, err := up.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	since, _ := strconv.ParseInt(r.URL.Query().Get("since_seq"), 10, 64)
	events, cancel := run.Journal.Subscribe(since)
	defer cancel()

	// Reader: only pongs + close detection.
	conn.SetReadLimit(512)
	_ = conn.SetReadDeadline(time.Now().Add(wsPongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsPongWait))
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ping := time.NewTicker(wsPingEvery)
	defer ping.Stop()
	for {
		select {
		case ev, open := <-events:
			if !open {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := conn.WriteJSON(ev); err != nil {
				return
			}
		case <-ping.C:
			_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case <-done:
			return
		}
	}
}
