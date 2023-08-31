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
	o.log.Info("Init done")
	return nil
}

// Shutdown stops the dummy offloading engine
func (o *DummyEngine) Shutdown() {
	if o.log == nil {
		return
	}
	o.log.Info("Shutdown done")
}

// Upsert imitates an offload creation between a client and a peer
func (o *DummyEngine) Upsert(client, peer Connection, _ []string) error {
	o.log.Debugf("Would create offload between client: %+v and peer: %+v", client, peer)
	return nil
}

// Remove imitates offload deletion between a client and a peer
func (o *DummyEngine) Remove(client, peer Connection) error {
	o.log.Debugf("Would remove offload between client: %+v and peer: %+v", client, peer)
	return nil
}
