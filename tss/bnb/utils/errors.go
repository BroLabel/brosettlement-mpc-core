package utils

import "errors"

var (
	ErrUnknownSenderParty       = errors.New("received frame from unknown party")
	ErrDuplicateFrame           = errors.New("duplicate frame")
	ErrFrameTooLarge            = errors.New("frame payload too large")
	ErrQueueFull                = errors.New("inbound queue is full")
	ErrStalledProtocol          = errors.New("protocol stalled")
	ErrKeyShareNotFound         = errors.New("ecdsa key share not found")
	ErrSignDigestRequired       = errors.New("sign digest is required")
	ErrSignAlgorithmUnsupported = errors.New("sign supports only ecdsa")
	ErrECDSAPubKeyUnavailable   = errors.New("ecdsa public key is unavailable")
)
