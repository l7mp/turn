// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package offload

import (
	"github.com/pion/logging"
)

// NullEngine is a null offload engine
type NullEngine struct {
	log logging.LeveledLogger
}

// NewNullEngine creates an uninitialized null offload engine
func NewNullEngine(log logging.LeveledLogger) (*NullEngine, error) {
	return &NullEngine{log: log}, nil
}

// Init initializes the Null engine
func (o *NullEngine) Init() error {
	o.log.Info("Init done")
	return nil
}

// Shutdown stops the null offloading engine
func (o *NullEngine) Shutdown() {
	if o.log == nil {
		return
	}
	o.log.Info("Shutdown done")
}

// Upsert imitates an offload creation between a client and a peer
func (o *NullEngine) Upsert(client, peer Connection) error {
	o.log.Debugf("Would create offload between client: %+v and peer: %+v", client, peer)
	return nil
}

// Remove imitates offload deletion between a client and a peer
func (o *NullEngine) Remove(client, peer Connection) error {
	o.log.Debugf("Would remove offload between client: %+v and peer: %+v", client, peer)
	return nil
}
