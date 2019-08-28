package krach

import (
	"sync"
)

type inMemoryIndex struct {
	rwLock *sync.RWMutex

	entries map[PeerIndex]*Session
}

func newInMemoryIndex() *inMemoryIndex {
	return &inMemoryIndex{
		rwLock:  &sync.RWMutex{},
		entries: make(map[PeerIndex]*Session),
	}
}

func (i *inMemoryIndex) AddPeer(index PeerIndex, peer *Session) {
	i.rwLock.Lock()
	defer i.rwLock.Unlock()
	i.entries[index] = peer
}

func (i *inMemoryIndex) RemovePeer(index PeerIndex) {
	i.rwLock.Lock()
	defer i.rwLock.Unlock()
	delete(i.entries, index)
}

func (i *inMemoryIndex) LookupPeer(index PeerIndex) *Session {
	i.rwLock.RLock()
	defer i.rwLock.RUnlock()
	return i.entries[index]
}
