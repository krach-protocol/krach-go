package krach

type Item interface {
	NeedsResource() bool
}

type roundrobin struct {
	items []Item
	idx   int
}
