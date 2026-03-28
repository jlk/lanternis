package fingerprint

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

var (
	reManufacturer = regexp.MustCompile(`(?i)<manufacturer[^>]*>([^<]*)</manufacturer>`)
	reModelName    = regexp.MustCompile(`(?i)<modelName[^>]*>([^<]*)</modelName>`)
	reModelNumber  = regexp.MustCompile(`(?i)<modelNumber[^>]*>([^<]*)</modelNumber>`)
	reFriendlyName = regexp.MustCompile(`(?i)<friendlyName[^>]*>([^<]*)</friendlyName>`)
	reSerial       = regexp.MustCompile(`(?i)<serialNumber[^>]*>([^<]*)</serialNumber>`)
)

// UPnPDevice holds fields extracted from a device description document.
type UPnPDevice struct {
	Manufacturer string
	ModelName    string
	ModelNumber  string
	FriendlyName string
	SerialNumber string
}

type xmlRoot struct {
	Device upnpXMLDevice `xml:"device"`
}

type upnpXMLDevice struct {
	Manufacturer string `xml:"manufacturer"`
	ModelName    string `xml:"modelName"`
	ModelNumber  string `xml:"modelNumber"`
	FriendlyName string `xml:"friendlyName"`
	SerialNumber string `xml:"serialNumber"`
}

// FetchUPnPDeviceDescription GETs locationURL (typically from SSDP) and parses device fields.
func FetchUPnPDeviceDescription(ctx context.Context, client *http.Client, locationURL string) (UPnPDevice, error) {
	var zero UPnPDevice
	if strings.TrimSpace(locationURL) == "" {
		return zero, fmt.Errorf("empty location")
	}
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, locationURL, nil)
	if err != nil {
		return zero, err
	}
	req.Header.Set("User-Agent", "Lanternis/1.0 UPnP-DeviceDescription")
	resp, err := client.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return zero, fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	if err != nil {
		return zero, err
	}
	return parseUPnPDescription(body), nil
}

func parseUPnPDescription(xmlBytes []byte) UPnPDevice {
	var root xmlRoot
	if err := xml.Unmarshal(xmlBytes, &root); err == nil && (root.Device.Manufacturer != "" || root.Device.ModelName != "") {
		return UPnPDevice{
			Manufacturer: strings.TrimSpace(root.Device.Manufacturer),
			ModelName:    strings.TrimSpace(root.Device.ModelName),
			ModelNumber:  strings.TrimSpace(root.Device.ModelNumber),
			FriendlyName: strings.TrimSpace(root.Device.FriendlyName),
			SerialNumber: strings.TrimSpace(root.Device.SerialNumber),
		}
	}
	// Namespace-quirky or partial XML: regex fallback.
	d := UPnPDevice{
		Manufacturer: firstSubmatch(reManufacturer, xmlBytes),
		ModelName:    firstSubmatch(reModelName, xmlBytes),
		ModelNumber:  firstSubmatch(reModelNumber, xmlBytes),
		FriendlyName: firstSubmatch(reFriendlyName, xmlBytes),
		SerialNumber: firstSubmatch(reSerial, xmlBytes),
	}
	return d
}

func firstSubmatch(re *regexp.Regexp, b []byte) string {
	m := re.FindSubmatch(b)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}
