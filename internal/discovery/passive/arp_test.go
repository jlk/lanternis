package passive

import (
	"reflect"
	"testing"
)

func TestParseLinuxProcNetARP(t *testing.T) {
	data := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
10.0.0.2         0x1         0x0         00:00:00:00:00:00     *        eth0
172.16.0.5       0x1         0x2         11:22:33:44:55:66     *        wlan0
`
	got := parseLinuxProcNetARP(data)
	want := []ARPEntry{
		{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:ff", Source: "linux_proc"},
		{IP: "172.16.0.5", MAC: "11:22:33:44:55:66", Source: "linux_proc"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseLinuxProcNetARP:\n got %#v\nwant %#v", got, want)
	}
}

func TestParseDarwinARPAn(t *testing.T) {
	data := `? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
? (10.0.0.2) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.99) at 11:22:33:44:55:66 on bridge100 ifscope [bridge]
`
	got := parseDarwinARPAn(data)
	want := []ARPEntry{
		{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:ff", Source: "darwin_arp"},
		{IP: "192.168.1.99", MAC: "11:22:33:44:55:66", Source: "darwin_arp"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseDarwinARPAn:\n got %#v\nwant %#v", got, want)
	}
}

func TestIPInCIDR(t *testing.T) {
	if !IPInCIDR("192.168.1.5", "192.168.1.0/24") {
		t.Fatal("expected 192.168.1.5 in 192.168.1.0/24")
	}
	if IPInCIDR("10.0.0.1", "192.168.1.0/24") {
		t.Fatal("expected 10.0.0.1 not in 192.168.1.0/24")
	}
}
