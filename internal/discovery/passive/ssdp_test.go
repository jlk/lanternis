package passive

import "testing"

func TestParseSSDPResponse(t *testing.T) {
	body := "HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=120\r\n" +
		"LOCATION: http://192.168.1.1:49152/rootDesc.xml\r\n" +
		"SERVER: OpenWRT/1.0 UPnP/1.1 MiniUPnPd/2.0\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"USN: uuid:deadbeef::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"\r\n"
	got := parseSSDPResponse(body)
	if got == nil {
		t.Fatal("expected parsed response")
	}
	if got.st != "urn:schemas-upnp-org:device:InternetGatewayDevice:1" {
		t.Fatalf("st: got %q", got.st)
	}
	if got.usn != "uuid:deadbeef::urn:schemas-upnp-org:device:InternetGatewayDevice:1" {
		t.Fatalf("usn: got %q", got.usn)
	}
	if got.server != "OpenWRT/1.0 UPnP/1.1 MiniUPnPd/2.0" {
		t.Fatalf("server: got %q", got.server)
	}
	if got.location != "http://192.168.1.1:49152/rootDesc.xml" {
		t.Fatalf("location: got %q", got.location)
	}
}

func TestParseSSDPResponseRejectsNonHTTP(t *testing.T) {
	if parseSSDPResponse("NOT HTTP\r\n") != nil {
		t.Fatal("expected nil")
	}
}

func TestUnionStrings(t *testing.T) {
	got := unionStrings([]string{"b", "a"}, []string{"a", "c"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}
