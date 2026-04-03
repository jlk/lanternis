package nmapenrich

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestParseNmapXMLGolden(t *testing.T) {
	b, err := os.ReadFile("testdata/minimal.xml")
	if err != nil {
		t.Fatal(err)
	}
	ports, err := ParseNmapXML(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 {
		t.Fatalf("ports: got %d want 2", len(ports))
	}
	if ports[0].Port != "80" || ports[0].Name != "http" || ports[0].Product != "nginx" {
		t.Fatalf("port 80: %#v", ports[0])
	}
	if ports[0].Scripts["http-title"] != "Welcome" {
		t.Fatalf("script: %#v", ports[0].Scripts)
	}
	if ports[1].Port != "22" || ports[1].Version != "8.4" {
		t.Fatalf("port 22: %#v", ports[1])
	}
}

func TestParseNmapXMLDOCTYPEWithoutInternalSubset(t *testing.T) {
	b, err := os.ReadFile("testdata/doctype_system.xml")
	if err != nil {
		t.Fatal(err)
	}
	ports, err := ParseNmapXML(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 1 || ports[0].Port != "22" {
		t.Fatalf("got %#v", ports)
	}
}

func TestParseNmapXMLRejectsInternalSubsetEntity(t *testing.T) {
	b, err := os.ReadFile("testdata/evil_internal_entity.xml")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseNmapXML(bytes.NewReader(b))
	if err == nil {
		t.Fatal("expected rejection")
	}
	if !errors.Is(err, ErrNmapXMLRejected) {
		t.Fatalf("expected ErrNmapXMLRejected in chain, got %v", err)
	}
}

func TestParseNmapXMLRejectsOversize(t *testing.T) {
	b := bytes.Repeat([]byte(" "), maxNmapXMLInputBytes+2)
	_, err := ParseNmapXML(bytes.NewReader(b))
	if err == nil {
		t.Fatal("expected oversize error")
	}
}

func TestParseNmapXMLRejectsNUL(t *testing.T) {
	b := []byte("<nmaprun>\x00</nmaprun>")
	_, err := ParseNmapXML(bytes.NewReader(b))
	if err == nil {
		t.Fatal("expected NUL rejection")
	}
}
