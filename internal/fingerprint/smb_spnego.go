package fingerprint

import (
	"encoding/asn1"

	"github.com/Azure/go-ntlmssp"
)

// SPNEGO + NTLM negotiate blob for SMB1 extended security (matches common smbclient / Windows behavior).
var (
	oidSPNEGO = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	oidNTLM   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
)

type spnegoInitialContext struct {
	ThisMech asn1.ObjectIdentifier `asn1:"optional"`
	Init     []spnegoNegTokenInit  `asn1:"optional,explicit,tag:0"`
}

type spnegoNegTokenInit struct {
	MechTypes []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	MechToken []byte                  `asn1:"explicit,tag:2"`
}

func buildSMBSessionSecurityBlob() ([]byte, error) {
	ntlm, err := ntlmssp.NewNegotiateMessage("", "")
	if err != nil {
		return nil, err
	}
	bs, err := asn1.Marshal(spnegoInitialContext{
		ThisMech: oidSPNEGO,
		Init: []spnegoNegTokenInit{{
			MechTypes: []asn1.ObjectIdentifier{oidNTLM},
			MechToken: ntlm,
		}},
	})
	if err != nil {
		return nil, err
	}
	if len(bs) > 0 {
		bs[0] = 0x60 // [APPLICATION 0] per MS-SPNG / Wireshark GSS-API
	}
	return bs, nil
}
