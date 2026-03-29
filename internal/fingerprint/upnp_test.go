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

func TestParseUPnPFirmwareAndDescription(t *testing.T) {
	xml := `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <manufacturer>Netgear</manufacturer>
    <modelName>Orbi</modelName>
    <modelDescription>Whole Home WiFi System</modelDescription>
    <softwareVersion>V2.7.3.22</softwareVersion>
  </device>
</root>`
	d := parseUPnPDescription([]byte(xml))
	if d.SoftwareVersion != "V2.7.3.22" {
		t.Fatalf("SoftwareVersion: got %q", d.SoftwareVersion)
	}
	if d.ModelDescription != "Whole Home WiFi System" {
		t.Fatalf("ModelDescription: got %q", d.ModelDescription)
	}

	xml2 := `<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<firmwareVersion>1.2.3</firmwareVersion>
</device></root>`
	d2 := parseUPnPDescription([]byte(xml2))
	if d2.SoftwareVersion != "1.2.3" {
		t.Fatalf("firmwareVersion → SoftwareVersion: got %+v", d2)
	}
}
