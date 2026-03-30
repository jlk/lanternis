// Package webenrich adds optional internet-assisted name hints (OpenAI or Anthropic) when the user opts in and stores an API key locally.
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

// openAIURL is the Chat Completions endpoint (overridable in tests).
var openAIURL = "https://api.openai.com/v1/chat/completions"

type openAIReq struct {
	Model            string          `json:"model"`
	Messages         []openAIMessage `json:"messages"`
	MaxTokens        int             `json:"max_tokens"`
	Temperature      float64         `json:"temperature"`
	ResponseFormat   map[string]string `json:"response_format,omitempty"`
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIResp struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func callOpenAI(ctx context.Context, apiKey, prompt string) (string, error) {
	reqBody := openAIReq{
		Model: "gpt-4o-mini",
		Messages: []openAIMessage{
			{Role: "user", Content: prompt},
		},
		MaxTokens:      320,
		Temperature:    0.2,
		ResponseFormat: map[string]string{"type": "json_object"},
	}
	raw, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, openAIURL, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
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
		return "", openaiHTTPError(resp.StatusCode, respBytes)
	}
	var wrap openAIResp
	if err := json.Unmarshal(respBytes, &wrap); err != nil {
		return "", err
	}
	if wrap.Error != nil && wrap.Error.Message != "" {
		return "", errors.New(wrap.Error.Message)
	}
	if len(wrap.Choices) == 0 {
		return "", errors.New("openai: empty choices")
	}
	return strings.TrimSpace(wrap.Choices[0].Message.Content), nil
}

func openaiHTTPError(status int, respBytes []byte) error {
	var wrap openAIResp
	if json.Unmarshal(respBytes, &wrap) == nil && wrap.Error != nil && strings.TrimSpace(wrap.Error.Message) != "" {
		return fmt.Errorf("openai http %d: %s", status, strings.TrimSpace(wrap.Error.Message))
	}
	s := strings.TrimSpace(string(respBytes))
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	if s == "" {
		return fmt.Errorf("openai http %d (empty body)", status)
	}
	return fmt.Errorf("openai http %d: %s", status, s)
}

type enrichJSON struct {
	Guess      string `json:"guess"`
	Confidence string `json:"confidence"`
	Note       string `json:"note"`
}

func parseEnrichmentJSON(s, defaultNote string) (guess, confidence, note string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", "", errors.New("empty content")
	}
	s = strings.TrimPrefix(s, "```json")
	s = strings.TrimPrefix(s, "```")
	s = strings.TrimSuffix(s, "```")
	s = strings.TrimSpace(s)
	var e enrichJSON
	if err := json.Unmarshal([]byte(s), &e); err != nil {
		return "", "", "", err
	}
	guess = strings.TrimSpace(e.Guess)
	conf := strings.ToLower(strings.TrimSpace(e.Confidence))
	switch conf {
	case "low", "medium", "high":
	default:
		conf = "low"
	}
	note = strings.TrimSpace(e.Note)
	if note == "" {
		note = defaultNote
	}
	return guess, conf, note, nil
}
