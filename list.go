package krach

import "sync"

type lst struct {
	elements []interface{}
	lock     *sync.Mutex
}

func newLst() *lst {
	return &lst{
		elements: make([]interface{}, 0),
		lock:     &sync.Mutex{},
	}
}

func (l *lst) Pop() interface{} {
	l.lock.Lock()
	defer l.lock.Unlock()
	if len(l.elements) == 0 {
		return nil
	}
	e := l.elements[0]
	l.elements = l.elements[1:]
	return e
}

func (l *lst) Push(e interface{}) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.elements = append(l.elements, e)
}
