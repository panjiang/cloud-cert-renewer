package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

type Notifier interface {
	Success(title, content string)
	Failure(title, content string)
}

type logOnlyNotifier struct{}

type feishuNotifier struct {
	url        string
	httpClient *http.Client
}

func NewNotifier(notifyURL string) Notifier {
	if strings.TrimSpace(notifyURL) == "" {
		return &logOnlyNotifier{}
	}
	return &feishuNotifier{
		url: notifyURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (n *logOnlyNotifier) Success(title, content string) {
	zap.L().Info(title, zap.String("content", content))
}

func (n *logOnlyNotifier) Failure(title, content string) {
	zap.L().Error(title, zap.String("content", content))
}

func (n *feishuNotifier) Success(title, content string) {
	if err := n.send(title, content); err != nil {
		zap.L().Error("send success notification failed", zap.Error(err))
	}
}

func (n *feishuNotifier) Failure(title, content string) {
	if err := n.send(title, content); err != nil {
		zap.L().Error("send failure notification failed", zap.Error(err))
	}
}

func (n *feishuNotifier) send(title, content string) error {
	body, err := json.Marshal(map[string]any{
		"msg_type": "text",
		"content": map[string]string{
			"text": title + "\n" + content,
		},
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}
	return nil
}
