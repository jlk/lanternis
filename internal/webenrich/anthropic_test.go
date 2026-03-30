package webenrich

import (
	"strings"
	"testing"
)

func TestAnthropicHTTPErrorParsesJSON(t *testing.T) {
	body := `{"type":"error","error":{"type":"not_found_error","message":"model: foo"}}`
	err := anthropicHTTPError(404, []byte(body))
	if err == nil || !strings.Contains(err.Error(), "model: foo") || !strings.Contains(err.Error(), "not_found_error") {
		t.Fatalf("got %v", err)
	}
}

func TestOpenaiHTTPErrorParsesJSON(t *testing.T) {
	body := `{"error":{"message":"Incorrect API key","type":"invalid_request_error"}}`
	err := openaiHTTPError(401, []byte(body))
	if err == nil || !strings.Contains(err.Error(), "Incorrect API key") {
		t.Fatalf("got %v", err)
	}
}
