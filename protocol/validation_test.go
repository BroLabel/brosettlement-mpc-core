package protocol_test

import (
	"testing"

	"github.com/BroLabel/brosettlement-mpc-core/protocol"
)

func TestIsValidSessionDescriptor_AllowsEmptyKeyID(t *testing.T) {
	session := protocol.SessionDescriptor{
		SessionID: "sess_1",
		OrgID:     "org_1",
		KeyID:     "",
		Parties:   []string{"p1", "p2", "p3"},
		Threshold: 2,
	}

	if !protocol.IsValidSessionDescriptor(session) {
		t.Fatal("expected session descriptor to be valid when key_id is empty")
	}
}

func TestIsValidSessionDescriptor_RequiresCoreFields(t *testing.T) {
	base := protocol.SessionDescriptor{
		SessionID: "sess_1",
		OrgID:     "org_1",
		Parties:   []string{"p1", "p2", "p3"},
		Threshold: 2,
	}

	cases := []struct {
		name    string
		session protocol.SessionDescriptor
	}{
		{
			name: "missing session id",
			session: protocol.SessionDescriptor{
				OrgID:     base.OrgID,
				Parties:   base.Parties,
				Threshold: base.Threshold,
			},
		},
		{
			name: "missing org id",
			session: protocol.SessionDescriptor{
				SessionID: base.SessionID,
				Parties:   base.Parties,
				Threshold: base.Threshold,
			},
		},
		{
			name: "no parties",
			session: protocol.SessionDescriptor{
				SessionID: base.SessionID,
				OrgID:     base.OrgID,
				Threshold: base.Threshold,
			},
		},
		{
			name: "zero threshold",
			session: protocol.SessionDescriptor{
				SessionID: base.SessionID,
				OrgID:     base.OrgID,
				Parties:   base.Parties,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if protocol.IsValidSessionDescriptor(tc.session) {
				t.Fatal("expected invalid session descriptor")
			}
		})
	}
}
