// Package bbolt implements the store.Store interface using bbolt (embedded B-tree).
//
// All values are stored as JSON. A single top-level bucket "agentintegrator"
// holds all keys. Transactions are serialisable (bbolt's read-write tx).
//
// Watch is implemented via an in-process fan-out: after each write, all
// watchers whose prefix matches the key receive an Event. This satisfies the
// control-plane requirement; it does NOT support cross-process watch.
package bbolt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/thev1ndu/agent-integrator/pkg/store"
)

const bucket = "agentintegrator"

// Store is the bbolt-backed implementation of store.Store.
type Store struct {
	db       *bolt.DB
	mu       sync.RWMutex
	watchers []*watcher
}

type watcher struct {
	prefix string
	ch     chan store.Event
	ctx    context.Context
}

// Open opens or creates the bbolt database at path.
func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("bbolt open %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucket))
		return err
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("bbolt init bucket: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Get(ctx context.Context, key string, out any) error {
	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		v := b.Get([]byte(key))
		if v == nil {
			return store.ErrNotFound
		}
		return json.Unmarshal(v, out)
	})
}

func (s *Store) List(ctx context.Context, prefix string, out any) error {
	outVal := reflect.ValueOf(out)
	if outVal.Kind() != reflect.Ptr || outVal.Elem().Kind() != reflect.Slice {
		return fmt.Errorf("store.List: out must be a pointer to a slice")
	}
	sliceVal := outVal.Elem()
	elemType := sliceVal.Type().Elem()

	return s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		c := b.Cursor()
		pfx := []byte(prefix)
		for k, v := c.Seek(pfx); k != nil && bytes.HasPrefix(k, pfx); k, v = c.Next() {
			elem := reflect.New(elemType).Interface()
			if err := json.Unmarshal(v, elem); err != nil {
				return fmt.Errorf("store.List unmarshal %s: %w", k, err)
			}
			sliceVal.Set(reflect.Append(sliceVal, reflect.ValueOf(elem).Elem()))
		}
		return nil
	})
}

func (s *Store) Put(ctx context.Context, key string, obj any, opts ...store.PutOption) error {
	v, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("store.Put marshal: %w", err)
	}

	var existed bool
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		existed = b.Get([]byte(key)) != nil
		return b.Put([]byte(key), v)
	}); err != nil {
		return err
	}

	evType := store.EventCreated
	if existed {
		evType = store.EventUpdated
	}
	s.notify(store.Event{Type: evType, Key: key, Object: v})
	return nil
}

func (s *Store) Delete(ctx context.Context, key string) error {
	if err := s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucket)).Delete([]byte(key))
	}); err != nil {
		return err
	}
	s.notify(store.Event{Type: store.EventDeleted, Key: key})
	return nil
}

func (s *Store) Watch(ctx context.Context, prefix string) (<-chan store.Event, error) {
	ch := make(chan store.Event, 64)
	w := &watcher{prefix: prefix, ch: ch, ctx: ctx}
	s.mu.Lock()
	s.watchers = append(s.watchers, w)
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		s.mu.Lock()
		for i, ww := range s.watchers {
			if ww == w {
				s.watchers = append(s.watchers[:i], s.watchers[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
		close(ch)
	}()
	return ch, nil
}

func (s *Store) Txn(ctx context.Context, fn func(store.Tx) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		return fn(&bboltTx{b: b})
	})
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) notify(ev store.Event) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, w := range s.watchers {
		if !bytes.HasPrefix([]byte(ev.Key), []byte(w.prefix)) {
			continue
		}
		select {
		case w.ch <- ev:
		default: // drop if consumer is slow; alert metrics should catch this
		}
	}
}

// bboltTx wraps a bolt.Bucket as store.Tx.
type bboltTx struct{ b *bolt.Bucket }

func (t *bboltTx) Get(key string, out any) error {
	v := t.b.Get([]byte(key))
	if v == nil {
		return store.ErrNotFound
	}
	return json.Unmarshal(v, out)
}

func (t *bboltTx) List(prefix string, out any) error {
	outVal := reflect.ValueOf(out)
	if outVal.Kind() != reflect.Ptr || outVal.Elem().Kind() != reflect.Slice {
		return fmt.Errorf("Tx.List: out must be a pointer to a slice")
	}
	sliceVal := outVal.Elem()
	elemType := sliceVal.Type().Elem()

	c := t.b.Cursor()
	pfx := []byte(prefix)
	for k, v := c.Seek(pfx); k != nil && bytes.HasPrefix(k, pfx); k, v = c.Next() {
		elem := reflect.New(elemType).Interface()
		if err := json.Unmarshal(v, elem); err != nil {
			return fmt.Errorf("Tx.List unmarshal %s: %w", k, err)
		}
		sliceVal.Set(reflect.Append(sliceVal, reflect.ValueOf(elem).Elem()))
	}
	return nil
}

func (t *bboltTx) Put(key string, obj any) error {
	v, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("Tx.Put marshal: %w", err)
	}
	return t.b.Put([]byte(key), v)
}

func (t *bboltTx) Delete(key string) error {
	return t.b.Delete([]byte(key))
}
