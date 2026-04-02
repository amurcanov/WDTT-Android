package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

var vkSemaphore = make(chan struct{}, 2)

var (
	sharedTransportOnce sync.Once
	sharedTransport     *http.Transport
)

var noDnsFlag atomic.Bool

func getSharedTransport() *http.Transport {
	sharedTransportOnce.Do(func() {
		dialer := &net.Dialer{
			Timeout: 10 * time.Second,
		}
		sharedTransport = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	})
	return sharedTransport
}

type Credentials struct {
	User     string
	Pass     string
	TurnURLs []string
}

func GetCredsWithFallback(ctx context.Context, tp *TurnParams, hash string, stats *Stats) (*Credentials, error) {
	creds, err := getUniqueVKCreds(ctx, hash, 5, stats)
	if err == nil {
		return creds, nil
	}
	if tp.SecondaryHash != "" && hash != tp.SecondaryHash {
		log.Println("Основной хеш не сработал, пробую запасной")
		return getUniqueVKCreds(ctx, tp.SecondaryHash, 3, stats)
	}
	return nil, err
}

func getUniqueVKCreds(ctx context.Context, hash string, maxRetries int, stats *Stats) (*Credentials, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case vkSemaphore <- struct{}{}:
		}

		creds, err := getVKCredsOnce(ctx, hash)
		<-vkSemaphore

		if err == nil {
			return creds, nil
		}

		atomic.AddInt64(&stats.CredsErrors, 1)
		lastErr = err
		errStr := err.Error()

		if strings.Contains(errStr, "9000") || strings.Contains(errStr, "call not found") {
			return nil, fmt.Errorf("хеш мёртв: %w", err)
		}

		var backoff time.Duration
		if strings.Contains(errStr, "flood") || strings.Contains(errStr, "Flood") {
			secs := 5 * (attempt + 1)
			if secs > 60 {
				secs = 60
			}
			backoff = time.Duration(secs) * time.Second
		} else {
			base := 1 << uint(min(attempt, 5))
			if base > 30 {
				base = 30
			}
			backoff = time.Duration(base)*time.Second + time.Duration(rand.Intn(1000))*time.Millisecond
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff):
		}
	}

	return nil, fmt.Errorf("исчерпаны %d попыток: %w", maxRetries, lastErr)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func getVKCredsOnce(ctx context.Context, hash string) (*Credentials, error) {
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: getSharedTransport(),
	}

	okAppKey := "CGMMEJLGDIHBABABA"
	appID := vkAppID.Load().(string)
	appSecret := vkAppSecret.Load().(string)

	doReq := func(data, url string) (map[string]interface{}, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBufferString(data))
		if err != nil {
			return nil, fmt.Errorf("создание запроса: %w", err)
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("чтение ответа: %w", err)
		}

		var m map[string]interface{}
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, fmt.Errorf("парсинг JSON: %w | Body: %s", err, string(body))
		}
		if errObj, ok := m["error"]; ok {
			return nil, fmt.Errorf("API error: %v | Body: %s", errObj, string(body))
		}
		return m, nil
	}

	get := func(m map[string]interface{}, keys ...string) (string, error) {
		var cur interface{} = m
		for _, k := range keys {
			mm, ok := cur.(map[string]interface{})
			if !ok {
				return "", fmt.Errorf("path %q not found", k)
			}
			cur = mm[k]
		}
		s, ok := cur.(string)
		if !ok {
			return "", fmt.Errorf("value at path is not string")
		}
		return s, nil
	}

	// 1: get anonymous token (с profile scopes и appSecret)
	r, err := doReq(fmt.Sprintf(
		"client_secret=%s&client_id=%s&scopes=audio_anonymous%%2Cvideo_anonymous%%2Cphotos_anonymous%%2Cprofile_anonymous&isApiOauthAnonymEnabled=false&version=1&app_id=%s",
		appSecret, appID, appID,
	), "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return nil, fmt.Errorf("шаг 1: %w", err)
	}
	t1, err := get(r, "data", "access_token")
	if err != nil {
		return nil, fmt.Errorf("шаг 1 парсинг: %w", err)
	}

	// 2: get messages token используя payload (t1)!!! (Это было пропущено)
	r, err = doReq(fmt.Sprintf(
		"client_id=%s&token_type=messages&payload=%s&client_secret=%s&version=1&app_id=%s",
		appID, t1, appSecret, appID,
	), "https://login.vk.ru/?act=get_anonym_token")
	if err != nil {
		return nil, fmt.Errorf("шаг 2: %w", err)
	}
	t3, err := get(r, "data", "access_token")
	if err != nil {
		return nil, fmt.Errorf("шаг 2 парсинг: %w", err)
	}

	// 3: get call token используя t3
	r, err = doReq(fmt.Sprintf(
		"vk_join_link=https://vk.com/call/join/%s&name=123&access_token=%s",
		hash, t3,
	), "https://api.vk.ru/method/calls.getAnonymousToken?v=5.264")
	if err != nil {
		return nil, fmt.Errorf("шаг 3: %w", err)
	}
	t4, err := get(r, "response", "token")
	if err != nil {
		return nil, fmt.Errorf("шаг 3 парсинг: %w", err)
	}

	// 4: OK anonymous login
	r, err = doReq(fmt.Sprintf(
		"session_data=%%7B%%22version%%22%%3A2%%2C%%22device_id%%22%%3A%%22%s%%22%%2C%%22client_version%%22%%3A1.1%%2C%%22client_type%%22%%3A%%22SDK_JS%%22%%7D&method=auth.anonymLogin&format=JSON&application_key=%s",
		uuid.New().String(), okAppKey,
	), "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return nil, fmt.Errorf("шаг 4: %w", err)
	}
	t5, err := get(r, "session_key")
	if err != nil {
		return nil, fmt.Errorf("шаг 4 парсинг: %w", err)
	}

	// 5: join conversation.
	r, err = doReq(fmt.Sprintf(
		"joinLink=%s&isVideo=false&protocolVersion=5&anonymToken=%s&method=vchat.joinConversationByLink&format=JSON&application_key=%s&session_key=%s",
		hash, t4, okAppKey, t5,
	), "https://calls.okcdn.ru/fb.do")
	if err != nil {
		return nil, fmt.Errorf("шаг 5: %w", err)
	}

	ts, ok := r["turn_server"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("turn_server не найден в ответе")
	}

	user, _ := ts["username"].(string)
	pass, _ := ts["credential"].(string)
	if user == "" || pass == "" {
		return nil, fmt.Errorf("пустые credentials в ответе")
	}

	lifetime, _ := ts["lifetime"].(float64)
	if lifetime > 0 {
		log.Printf("[ВК] Креды получены ✓ (LIFE: %.0f сек)", lifetime)
	} else {
		log.Printf("[ВК] Креды получены ✓")
	}

	urls, _ := ts["urls"].([]interface{})
	var turnAddrs []string
	for _, u := range urls {
		s, ok := u.(string)
		if !ok {
			continue
		}
		clean := strings.Split(s, "?")[0]
		addr := strings.TrimPrefix(strings.TrimPrefix(clean, "turn:"), "turns:")
		if addr != "" {
			turnAddrs = append(turnAddrs, addr)
		}
	}
	if len(turnAddrs) == 0 {
		return nil, fmt.Errorf("нет TURN urls в ответе")
	}

	return &Credentials{User: user, Pass: pass, TurnURLs: turnAddrs}, nil
}
