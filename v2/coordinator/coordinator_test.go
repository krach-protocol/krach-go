package coordinator

import (
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testRequestor struct {
	id   int
	used bool
}

func (t *testRequestor) Acquire(item interface{}) {
	t.used = true
	i := item.(*[]int)
	// Simulate some work
	randMillis := rand.Intn(200)
	time.Sleep(time.Millisecond * time.Duration(randMillis))
	if len(*i) <= t.id {
		*i = append(*i, t.id)
	}

}

func TestAccess(t *testing.T) {
	item := []int{}

	rr := NewRoundRobin(&item)

	reqCount := 100
	requestors := make([]*testRequestor, reqCount)

	for i := 0; i < reqCount; i++ {
		requestors[i] = &testRequestor{
			id:   i,
			used: false,
		}
		rr.AddRequester(requestors[i])
	}

	wg := sync.WaitGroup{}
	for i := 0; i < reqCount; i++ {
		wg.Add(1)
		go func(tr *testRequestor) {
			defer wg.Done()
			for !tr.used {
				rr.TryMove()
			}
		}(requestors[i])
	}
	wg.Wait()

	assert.Len(t, item, reqCount)

	for i := 0; i < reqCount; i++ {
		assert.Equal(t, i, item[i])
	}
}
