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
	system := "You reply with a single JSON object only, no markdown fences. Keys: guess (string), confidence (\"low\"|\"medium\"|\"high\"), note (string)."
	reqBody := anthropicReq{
		Model:     "claude-3-5-haiku-20241022",
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
		return "", fmt.Errorf("anthropic http %d", resp.StatusCode)
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
