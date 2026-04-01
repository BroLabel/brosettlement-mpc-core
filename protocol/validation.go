package protocol

func IsValidFrame(frame Frame) bool {
	return frame.SessionID != "" && frame.OrgID != "" && frame.FromParty != ""
}

func IsValidSessionDescriptor(session SessionDescriptor) bool {
	if session.SessionID == "" || session.OrgID == "" {
		return false
	}
	if len(session.Parties) == 0 || session.Threshold == 0 {
		return false
	}
	return true
}
