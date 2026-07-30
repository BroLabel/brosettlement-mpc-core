package tss

import "github.com/BroLabel/brosettlement-mpc-core/internal/preparams"

var (
	ErrInvalidPreParamsHandle = preparams.ErrInvalidPreParamsHandle
	ErrForeignPreParamsHandle = preparams.ErrForeignPreParamsHandle
	ErrPreParamsConsumed      = preparams.ErrPreParamsConsumed
	ErrPreParamsDiscarded     = preparams.ErrPreParamsDiscarded
)

// DKGPreParamsHandle is an opaque, service-bound, single-use DKG resource.
type DKGPreParamsHandle interface {
	Discard() error
	dkgPreParamsHandle()
}

type dkgPreParamsHandle struct {
	handle *preparams.Handle
}

func (h *dkgPreParamsHandle) Discard() error {
	if h == nil || h.handle == nil {
		return ErrInvalidPreParamsHandle
	}
	return h.handle.Discard()
}

func (*dkgPreParamsHandle) dkgPreParamsHandle() {}

func unwrapDKGPreParamsHandle(handle DKGPreParamsHandle) (*preparams.Handle, error) {
	internal, ok := handle.(*dkgPreParamsHandle)
	if !ok || internal == nil || internal.handle == nil {
		return nil, ErrInvalidPreParamsHandle
	}
	return internal.handle, nil
}

var _ DKGPreParamsHandle = (*dkgPreParamsHandle)(nil)
