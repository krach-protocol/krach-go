package coordinator

import (
	"errors"
	"sync"
	"sync/atomic"
)

type RoundRobin struct {
	item interface{}

	index          int
	requesters     []Requester
	requestersLock *sync.Mutex
	tryLock        int32
}

type Requester interface {
	Acquire(item interface{})
}

func NewRoundRobin(item interface{}) *RoundRobin {
	return &RoundRobin{
		item:           item,
		requesters:     []Requester{},
		requestersLock: &sync.Mutex{},
	}
}

func (r *RoundRobin) AddRequester(req Requester) {
	r.requestersLock.Lock()
	defer r.requestersLock.Unlock()
	r.requesters = append(r.requesters, req)
}

func (r *RoundRobin) RemoveRequester(req Requester) {
	r.requestersLock.Lock()
	defer r.requestersLock.Unlock()
	for i, rq := range r.requesters {
		if rq == req {
			r.requesters = append(r.requesters[:i], r.requesters[i+1:]...)
			break
		}
	}
}

func (r *RoundRobin) TryMove() error {
	if !atomic.CompareAndSwapInt32(&r.tryLock, 0, 1) {
		// If we can't swap this, another goroutine is already trying
		return nil
	}
	r.requestersLock.Lock()
	defer r.requestersLock.Unlock()

	nextIndex := r.index
	if nextIndex >= len(r.requesters) {
		nextIndex = 0
	}

	req := r.requesters[nextIndex]

	req.Acquire(r.item)

	r.index = nextIndex + 1

	if !atomic.CompareAndSwapInt32(&r.tryLock, 1, 0) {
		// This should never happen
		atomic.StoreInt32(&r.tryLock, 0)
		return errors.New("RoundRobin invalid state, tried to free tryLock, but it was already free")
	}
	return nil
}
