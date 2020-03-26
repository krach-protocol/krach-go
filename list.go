package krach

import "container/list"

type lst struct {
	list.List
}

func newLst() *lst {
	cl := list.New()
	cl.Init()
	return &lst{*cl}
}

func (l *lst) Pop() interface{} {
	e := l.Front()
	l.Remove(e)
	return e.Value
}

func (l *lst) Push(e interface{}) {
	l.PushBack(e)
}
