package shares

import "time"

const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

type ShareMeta struct {
	KeyID     string
	OrgID     string
	Algorithm string
	Curve     string
	CreatedAt time.Time
	Version   uint32
	Status    string
}
