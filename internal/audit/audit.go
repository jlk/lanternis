package audit

import (
	"context"
	"encoding/json"
)

type EventWriter interface {
	InsertAuditEvent(ctx context.Context, eventType string, payloadJSON string) error
}

func Append(ctx context.Context, w EventWriter, eventType string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return w.InsertAuditEvent(ctx, eventType, string(raw))
}
