package antinuke

import (
	"sync"
	"time"

	"sentinel-adaptive/internal/utils"
)

type Module struct {
	mu      sync.Mutex
	windows map[string]*utils.SlidingWindow
	window  time.Duration
}

func New(window time.Duration) *Module {
	if window <= 0 {
		window = 20 * time.Second
	}
	return &Module{windows: make(map[string]*utils.SlidingWindow), window: window}
}

func (m *Module) SetWindow(window time.Duration) {
	if window <= 0 {
		return
	}
	m.mu.Lock()
	m.window = window
	m.mu.Unlock()
}

func (m *Module) Count(guildID, actorID, action string) int {
	key := guildID + ":" + actorID + ":" + action
	window := m.getWindow(key)
	return window.Add(time.Now())
}

func (m *Module) getWindow(key string) *utils.SlidingWindow {
	m.mu.Lock()
	defer m.mu.Unlock()
	window := m.windows[key]
	if window == nil {
		window = utils.NewSlidingWindow(m.window)
		m.windows[key] = window
	}
	return window
}
