package preparams

import (
	"errors"
	"sync"

	ecdsakeygen "github.com/bnb-chain/tss-lib/ecdsa/keygen"
)

var (
	ErrInvalidPreParamsHandle = errors.New("invalid dkg preparams handle")
	ErrForeignPreParamsHandle = errors.New("dkg preparams handle belongs to another service")
	ErrPreParamsConsumed      = errors.New("dkg preparams handle is consumed")
	ErrPreParamsDiscarded     = errors.New("dkg preparams handle is discarded")
)

type handleState uint8

const (
	handleStateInvalid handleState = iota
	handleStateAcquired
	handleStateConsumed
	handleStateDiscarded
)

// ServiceBinding identifies the service instance that owns a handle.
type ServiceBinding struct {
	_ byte
}

// Handle owns one opaque set of DKG pre-parameters.
type Handle struct {
	mu       sync.Mutex
	binding  *ServiceBinding
	state    handleState
	material *ecdsakeygen.LocalPreParams
}

func NewServiceBinding() *ServiceBinding {
	return &ServiceBinding{}
}

func NewHandle(binding *ServiceBinding, material *ecdsakeygen.LocalPreParams) *Handle {
	if binding == nil || material == nil {
		return nil
	}
	return &Handle{
		binding:  binding,
		state:    handleStateAcquired,
		material: material,
	}
}

func (h *Handle) Discard() error {
	if h == nil {
		return ErrInvalidPreParamsHandle
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.validLocked() {
		return ErrInvalidPreParamsHandle
	}

	switch h.state {
	case handleStateAcquired:
		h.material = nil
		h.state = handleStateDiscarded
		return nil
	case handleStateDiscarded:
		return nil
	case handleStateConsumed:
		return ErrPreParamsConsumed
	default:
		return ErrInvalidPreParamsHandle
	}
}

func Consume(binding *ServiceBinding, handle *Handle) (*ecdsakeygen.LocalPreParams, error) {
	if binding == nil || handle == nil {
		return nil, ErrInvalidPreParamsHandle
	}

	handle.mu.Lock()
	defer handle.mu.Unlock()
	if !handle.validLocked() {
		return nil, ErrInvalidPreParamsHandle
	}
	if handle.binding != binding {
		return nil, ErrForeignPreParamsHandle
	}

	switch handle.state {
	case handleStateAcquired:
		material := handle.material
		handle.material = nil
		handle.state = handleStateConsumed
		return material, nil
	case handleStateConsumed:
		return nil, ErrPreParamsConsumed
	case handleStateDiscarded:
		return nil, ErrPreParamsDiscarded
	default:
		return nil, ErrInvalidPreParamsHandle
	}
}

func (h *Handle) validLocked() bool {
	if h.binding == nil || h.state == handleStateInvalid {
		return false
	}
	return h.state != handleStateAcquired || h.material != nil
}
