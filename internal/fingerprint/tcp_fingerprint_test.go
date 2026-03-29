package fingerprint

import "testing"

func TestMatchSynAckRulesLinuxLike(t *testing.T) {
	t.Parallel()
	f := SynAckFeat{TTL: 64, Win: 64240, MSS: 1460, WS: 7, SACK: true, TS: true}
	fam, _, score, ok := matchSynAckRules(f)
	if !ok || fam != OSFamilyLinux || score < 40 {
		t.Fatalf("got %q ok=%v score=%d", fam, ok, score)
	}
}
