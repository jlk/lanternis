package webenrich

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// anthropicMessagesURL is overridable in tests.
var anthropicMessagesURL = "https://api.anthropic.com/v1/messages"

// anthropicModel is a current Haiku snapshot (3.5-era IDs such as claude-3-5-haiku-20241022 return 404 after retirement).
const anthropicModel = "claude-haiku-4-5-20251001"

type anthropicReq struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system,omitempty"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResp struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

func callAnthropic(ctx context.Context, apiKey, userPrompt string) (string, error) {
	system := "You reply with a single JSON object only, no markdown fences. Keys: guess, confidence (low|medium|high), note, vendor (brand or empty), device_class_key (printer|camera|nas|router|home_automation|media|game_console|mobile|server|audio|computer|network|iot or empty), os_family (linux|windows|darwin|embedded or empty)."
	reqBody := anthropicReq{
		Model:     anthropicModel,
		MaxTokens: 320,
		System:    system,
		Messages: []anthropicMessage{
			{Role: "user", Content: userPrompt},
		},
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicMessagesURL, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("x-api-key", strings.TrimSpace(apiKey))
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 14 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", anthropicHTTPError(resp.StatusCode, respBytes)
	}
	var wrap anthropicResp
	if err := json.Unmarshal(respBytes, &wrap); err != nil {
		return "", err
	}
	if wrap.Error != nil && wrap.Error.Message != "" {
		return "", errors.New(wrap.Error.Message)
	}
	for _, block := range wrap.Content {
		if block.Type == "text" && strings.TrimSpace(block.Text) != "" {
			return strings.TrimSpace(block.Text), nil
		}
	}
	return "", errors.New("anthropic: empty content")
}

// anthropicHTTPError turns a failed status into an error that includes the API message when present
// (404 often means unknown or retired model; 401 invalid key).
func anthropicHTTPError(status int, respBytes []byte) error {
	var wrap anthropicResp
	if json.Unmarshal(respBytes, &wrap) == nil && wrap.Error != nil && strings.TrimSpace(wrap.Error.Message) != "" {
		t := strings.TrimSpace(wrap.Error.Type)
		if t != "" {
			return fmt.Errorf("anthropic http %d: %s (error.type=%s)", status, strings.TrimSpace(wrap.Error.Message), t)
		}
		return fmt.Errorf("anthropic http %d: %s", status, strings.TrimSpace(wrap.Error.Message))
	}
	s := strings.TrimSpace(string(respBytes))
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	if s == "" {
		return fmt.Errorf("anthropic http %d (empty body)", status)
	}
	return fmt.Errorf("anthropic http %d: %s", status, s)
}
