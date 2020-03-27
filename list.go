package krach

type lst struct {
	elements []interface{}
}

func newLst() *lst {
	return &lst{
		elements: make([]interface{}, 0),
	}
}

func (l *lst) Pop() interface{} {
	if len(l.elements) == 0 {
		return nil
	}
	e := l.elements[0]
	l.elements = l.elements[1:]
	return e
}

func (l *lst) Push(e interface{}) {
	l.elements = append(l.elements, e)
}
