package protocol

import "time"

type Frame struct {
	SessionID     string
	Stage         string
	OrgID         string
	MessageID     string
	Seq           uint64
	Round         uint32
	RoundHint     uint32
	Broadcast     bool
	Protocol      string
	MessageType   string
	PayloadHash   string
	FromParty     string
	ToParty       string
	Payload       []byte
	CorrelationID string
	SentAt        time.Time
}

func (f Frame) IsBroadcast() bool {
	// backward compatibility for producers that only set ToParty=""
	return f.Broadcast || f.ToParty == ""
}
