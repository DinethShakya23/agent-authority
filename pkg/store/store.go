// Copyright 2026 Agent Integrator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import "context"

type Store interface {
	Get(ctx context.Context, key string, out any) error
	List(ctx context.Context, prefix string, out any) error
	Put(ctx context.Context, key string, obj any, opts ...PutOption) error
	Delete(ctx context.Context, key string) error
	Watch(ctx context.Context, prefix string) (<-chan Event, error)
	Txn(ctx context.Context, fn func(Tx) error) error
	Close() error
}

type Tx interface {
	Get(key string, out any) error
	List(prefix string, out any) error
	Put(key string, obj any) error
	Delete(key string) error
}

type Event struct {
	Type   EventType
	Key    string
	Object []byte
}

type EventType string

const (
	EventCreated EventType = "Created"
	EventUpdated EventType = "Updated"
	EventDeleted EventType = "Deleted"
)

type PutOption func(*putOptions)

type putOptions struct {
	ttl      int64
	revision int64
}

func WithTTL(seconds int64) PutOption {
	return func(o *putOptions) { o.ttl = seconds }
}

func WithRevision(rev int64) PutOption {
	return func(o *putOptions) { o.revision = rev }
}

var ErrNotFound = &storeError{msg: "not found"}

var ErrConflict = &storeError{msg: "revision conflict"}

type storeError struct{ msg string }

func (e *storeError) Error() string { return "store: " + e.msg }
