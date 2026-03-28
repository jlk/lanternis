package fingerprint

import "testing"

func TestParseUPnPDescription(t *testing.T) {
	xml := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
    <friendlyName>Living Room TV</friendlyName>
    <manufacturer>Example Corp</manufacturer>
    <modelName>XR-500</modelName>
    <modelNumber>1.0</modelNumber>
    <serialNumber>SN123</serialNumber>
  </device>
</root>`
	d := parseUPnPDescription([]byte(xml))
	if d.Manufacturer != "Example Corp" || d.ModelName != "XR-500" || d.SerialNumber != "SN123" {
		t.Fatalf("parse: got %+v", d)
	}
}
