package protocol

type SessionDescriptor struct {
	SessionID string
	OrgID     string
	KeyID     string
	Parties   []string
	Threshold uint32
	Algorithm string
	Curve     string
	Chain     string
}
