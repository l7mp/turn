package offload

import (
	"github.com/pion/logging"
)

// DummyEngine is a dummy offload engine
type DummyEngine struct {
	log logging.LeveledLogger
}

// NewDummyEngine creates an uninitialized dummy offload engine
func NewDummyEngine(log logging.LeveledLogger) (*DummyEngine, error) {
	return &DummyEngine{log: log}, nil
}

// Logger returns the offload engine's logger
func (o *DummyEngine) Logger() logging.LeveledLogger {
	return o.log
}

// Init initializes the Dummy engine
func (o *DummyEngine) Init() error {
	o.log.Debug("dummy: init done")
	return nil
}

// Shutdown stops the dummy offloading engine
func (o *DummyEngine) Shutdown() error {
	if o.log == nil {
		return nil
	}
	o.log.Debug("dummy: shutdown done")
	return nil
}

// Upsert imitates an offload creation between a peer and a client
func (o *DummyEngine) Upsert(peer, client Connection, _ []string) error {
	o.log.Debugf("dummy: would create offload between peer: %+v and client: %+v", peer, client)
	return nil
}

// Remove imitates offload deletion between a peer and a client
func (o *DummyEngine) Remove(peer, client Connection) error {
	o.log.Debugf("dummy: would remove offload between peer: %+v and client: %+v", peer, client)
	return nil
}
