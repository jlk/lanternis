package passive

import "testing"

func TestLANBindingForCIDRInvalid(t *testing.T) {
	_, err := LANBindingForCIDR("not-a-cidr")
	if err == nil {
		t.Fatal("expected error")
	}
}
