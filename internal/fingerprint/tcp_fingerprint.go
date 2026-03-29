package fingerprint

import "strings"

// matchSynAckRules maps decoded SYN-ACK features to a coarse OS guess (heuristic, IoT/LAN-oriented).
// Not cryptographic proof; combined with tiered fusion in mergeOSEvidence.
func matchSynAckRules(f SynAckFeat) (family, detail string, score int, ok bool) {
	// Linux-class / embedded stacks: common LAN TTL 64, MSS 1460, SACK, window scaling.
	if f.TTL > 0 && f.TTL <= 64 && f.MSS == 1460 && f.SACK && f.WS >= 0 && f.WS <= 14 {
		return OSFamilyLinux, "TCP stack resembles Linux / embedded (SYN-ACK shape)", 52, true
	}
	// Windows-ish: TTL often 128 on LAN, initial window patterns vary; conservative match.
	if f.TTL >= 115 && f.TTL <= 128 && f.Win >= 8192 && f.MSS == 1460 {
		return OSFamilyWindows, "TCP stack resembles Windows class (SYN-ACK shape)", 48, true
	}
	// Some BSD / network appliances: TTL 64, smaller windows without full option set.
	if f.TTL > 0 && f.TTL <= 64 && f.Win > 0 && f.Win < 16000 && !f.SACK {
		return OSFamilyEmbedded, "TCP stack resembles appliance / BSD-like (SYN-ACK shape)", 44, true
	}
	return "", "", 0, false
}

// AppendTCPGuess appends a machine-parsable guess clause for ApplyOSInference.
func AppendTCPGuess(hint string, family, detail string) string {
	if family == "" {
		return hint
	}
	var b strings.Builder
	b.WriteString(hint)
	b.WriteString(" | guess=")
	b.WriteString(family)
	b.WriteString(":")
	b.WriteString(detail)
	return b.String()
}
