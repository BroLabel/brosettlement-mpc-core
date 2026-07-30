package preparams

import (
	"errors"
	"sync"
	"testing"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

func TestHandleRejectsNilAndForgedValues(t *testing.T) {
	binding := NewServiceBinding()

	if _, err := Consume(binding, nil); !errors.Is(err, ErrInvalidPreParamsHandle) {
		t.Fatalf("nil consume error = %v, want ErrInvalidPreParamsHandle", err)
	}

	forged := &Handle{}
	if err := forged.Discard(); !errors.Is(err, ErrInvalidPreParamsHandle) {
		t.Fatalf("forged discard error = %v, want ErrInvalidPreParamsHandle", err)
	}
	if _, err := Consume(binding, forged); !errors.Is(err, ErrInvalidPreParamsHandle) {
		t.Fatalf("forged consume error = %v, want ErrInvalidPreParamsHandle", err)
	}
	if got := binding.Snapshot(); got != (HandleMetrics{}) {
		t.Fatalf("invalid attempts changed metrics: %+v", got)
	}
}

func TestHandleRejectsForeignServiceWithoutConsuming(t *testing.T) {
	owner := NewServiceBinding()
	foreign := NewServiceBinding()
	handle := NewHandle(owner, &ecdsakeygen.LocalPreParams{})

	if _, err := Consume(foreign, handle); !errors.Is(err, ErrForeignPreParamsHandle) {
		t.Fatalf("foreign consume error = %v, want ErrForeignPreParamsHandle", err)
	}
	if got := foreign.Snapshot(); got != (HandleMetrics{}) {
		t.Fatalf("foreign attempt changed foreign metrics: %+v", got)
	}
	if got := owner.Snapshot(); got != (HandleMetrics{}) {
		t.Fatalf("foreign attempt changed owner metrics: %+v", got)
	}
	if _, err := Consume(owner, handle); err != nil {
		t.Fatalf("owner consume failed after foreign attempt: %v", err)
	}
	if _, err := Consume(foreign, handle); !errors.Is(err, ErrForeignPreParamsHandle) {
		t.Fatalf("foreign consume after owner transition error = %v, want ErrForeignPreParamsHandle", err)
	}
	if got := foreign.Snapshot(); got != (HandleMetrics{}) {
		t.Fatalf("foreign terminal-state attempt changed foreign metrics: %+v", got)
	}
	if got := owner.Snapshot(); got != (HandleMetrics{ConsumedCount: 1}) {
		t.Fatalf("foreign terminal-state attempt changed owner metrics: %+v", got)
	}
}

func TestHandleDiscardIsIdempotentAndBlocksConsume(t *testing.T) {
	binding := NewServiceBinding()
	handle := NewHandle(binding, &ecdsakeygen.LocalPreParams{})

	if err := handle.Discard(); err != nil {
		t.Fatalf("first discard failed: %v", err)
	}
	if err := handle.Discard(); err != nil {
		t.Fatalf("repeated discard failed: %v", err)
	}
	if _, err := Consume(binding, handle); !errors.Is(err, ErrPreParamsDiscarded) {
		t.Fatalf("consume after discard error = %v, want ErrPreParamsDiscarded", err)
	}
	if _, err := Consume(binding, handle); !errors.Is(err, ErrPreParamsDiscarded) {
		t.Fatalf("repeated consume after discard error = %v, want ErrPreParamsDiscarded", err)
	}
	want := HandleMetrics{DiscardedBeforeStartCount: 1, ConsumeConflictCount: 2}
	if got := binding.Snapshot(); got != want {
		t.Fatalf("metrics = %+v, want %+v", got, want)
	}
}

func TestHandleConsumedStateRejectsDiscardAndRepeatedConsume(t *testing.T) {
	binding := NewServiceBinding()
	handle := NewHandle(binding, &ecdsakeygen.LocalPreParams{})

	if _, err := Consume(binding, handle); err != nil {
		t.Fatalf("initial consume failed: %v", err)
	}
	if err := handle.Discard(); !errors.Is(err, ErrPreParamsConsumed) {
		t.Fatalf("discard after consume error = %v, want ErrPreParamsConsumed", err)
	}
	if _, err := Consume(binding, handle); !errors.Is(err, ErrPreParamsConsumed) {
		t.Fatalf("repeated consume error = %v, want ErrPreParamsConsumed", err)
	}
	if _, err := Consume(binding, handle); !errors.Is(err, ErrPreParamsConsumed) {
		t.Fatalf("second repeated consume error = %v, want ErrPreParamsConsumed", err)
	}
	want := HandleMetrics{ConsumedCount: 1, ConsumeConflictCount: 2}
	if got := binding.Snapshot(); got != want {
		t.Fatalf("metrics = %+v, want %+v", got, want)
	}
}

func TestHandleConcurrentConsumeDiscardHasExactlyOneWinner(t *testing.T) {
	for iteration := 0; iteration < 200; iteration++ {
		binding := NewServiceBinding()
		handle := NewHandle(binding, &ecdsakeygen.LocalPreParams{})
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)

		var consumeErr error
		var discardErr error
		go func() {
			defer wg.Done()
			<-start
			_, consumeErr = Consume(binding, handle)
		}()
		go func() {
			defer wg.Done()
			<-start
			discardErr = handle.Discard()
		}()

		close(start)
		wg.Wait()

		switch {
		case consumeErr == nil:
			if !errors.Is(discardErr, ErrPreParamsConsumed) {
				t.Fatalf("iteration %d: consume won, discard error = %v", iteration, discardErr)
			}
			want := HandleMetrics{ConsumedCount: 1}
			if got := binding.Snapshot(); got != want {
				t.Fatalf("iteration %d: metrics = %+v, want %+v", iteration, got, want)
			}
		case discardErr == nil:
			if !errors.Is(consumeErr, ErrPreParamsDiscarded) {
				t.Fatalf("iteration %d: discard won, consume error = %v", iteration, consumeErr)
			}
			want := HandleMetrics{DiscardedBeforeStartCount: 1, ConsumeConflictCount: 1}
			if got := binding.Snapshot(); got != want {
				t.Fatalf("iteration %d: metrics = %+v, want %+v", iteration, got, want)
			}
		default:
			t.Fatalf("iteration %d: no transition winner: consume=%v discard=%v", iteration, consumeErr, discardErr)
		}
	}
}
