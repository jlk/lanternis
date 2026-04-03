package nmapenrich

import (
	"encoding/json"
	"strings"

	"github.com/jlk/lanternis/internal/fingerprint"
)

// AppendParsedPortsToRecord adds one nmap signal per parsed open port.
func AppendParsedPortsToRecord(rec *fingerprint.Record, ports []ParsedPort) {
	if rec == nil || len(ports) == 0 {
		return
	}
	for _, p := range ports {
		if strings.TrimSpace(p.Port) == "" {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(p.Proto))
		if proto == "" {
			proto = "tcp"
		}
		pl := fingerprint.NmapServicePayload{
			Proto:     proto,
			Port:      strings.TrimSpace(p.Port),
			Name:      p.Name,
			Product:   p.Product,
			Version:   p.Version,
			Extrainfo: p.Extrainfo,
			Scripts:   p.Scripts,
		}
		if len(pl.Scripts) == 0 {
			pl.Scripts = nil
		}
		raw, err := json.Marshal(pl)
		if err != nil {
			continue
		}
		rec.Signals = append(rec.Signals, fingerprint.Signal{
			Source: "nmap",
			Field:  "service:" + proto + ":" + pl.Port,
			Value:  string(raw),
		})
	}
}
