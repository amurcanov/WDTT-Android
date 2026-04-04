package main

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

const (
	workersPerGroup = 12
	cycleSecs       = 840 // 
	phaseStepSec    = 16  // 
)

// WorkerGroup:
// бесшовная ротация: получить новые креды → запустить новый батч → убить старый.
func WorkerGroup(
	ctx context.Context,
	groupID int,
	hashIndex int,
	tp *TurnParams,
	peer *net.UDPAddr,
	d *Dispatcher,
	localPort string,
	useUDP bool,
	getConfig bool,
	configCh chan<- string,
	workerIDs []int,
	initialDelay time.Duration,
	cycleDuration time.Duration,
	pauseFlag *int32,
	deviceID, password string,
	stats *Stats,
) {
	// Фазовый сдвиг
	if initialDelay > 0 {
		log.Printf("[ГРУППА #%d] Фазовый сдвиг: %v", groupID, initialDelay)
		select {
		case <-time.After(initialDelay):
		case <-ctx.Done():
			return
		}
	}

	cycleNumber := 0
	configSent := !getConfig

	// Предыдущий батч
	var prevCancel context.CancelFunc
	var prevDoneChs []chan struct{}

	killBatch := func() {
		if prevCancel != nil {
			prevCancel()
			for _, ch := range prevDoneChs {
				select {
				case <-ch:
				case <-time.After(3 * time.Second):
				}
			}
			prevCancel = nil
			prevDoneChs = nil
		}
	}
	defer killBatch()

	for {
		if ctx.Err() != nil {
			return
		}

		// Doze-mode пауза: убиваем воркеров и ждём RESUME
		if atomic.LoadInt32(pauseFlag) != 0 {
			killBatch()
			log.Printf("[ГРУППА #%d] Пауза (Doze)", groupID)
			for {
				if ctx.Err() != nil {
					return
				}
				if atomic.LoadInt32(pauseFlag) == 0 {
					log.Printf("[ГРУППА #%d] Возобновление — новые креды", groupID)
					break
				}
				time.Sleep(1 * time.Second)
			}
		}

		// Получаем креды ДО убийства старого батча (бесшовная ротация)
		hash := tp.Hashes[hashIndex%len(tp.Hashes)]
		shortHash := hash
		if len(shortHash) > 8 {
			shortHash = shortHash[:8]
		}
		log.Printf("[ГРУППА #%d] Цикл %d: запрос кредов (хеш: %s...)", groupID, cycleNumber, shortHash)

		creds, err := GetCredsWithFallback(ctx, tp, hash, stats)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("[ГРУППА #%d] Ошибка кредов: %v", groupID, err)
			select {
			case <-time.After(30 * time.Second):
			case <-ctx.Done():
				return
			}
			continue
		}

		log.Printf("[ГРУППА #%d] Креды OK, TURN: %v, %d воркеров", groupID, creds.TurnURLs, len(workerIDs))

		// ТЕПЕРЬ убиваем старый батч (креды уже готовы — минимальный простой)
		killBatch()

		// Создаём новый batch
		batchCtx, batchCancel := context.WithCancel(ctx)
		var configNeeded int32
		if !configSent {
			configNeeded = 1
		}

		doneChs := make([]chan struct{}, len(workerIDs))

		for i, wid := range workerIDs {
			doneCh := make(chan struct{})
			doneChs[i] = doneCh

			// Stagger: 500мс между воркерами
			workerDelay := time.Duration(i) * 500 * time.Millisecond

			go func(wid int, delay time.Duration, doneCh chan struct{}) {
				defer close(doneCh)

				if delay > 0 {
					select {
					case <-time.After(delay):
					case <-batchCtx.Done():
						return
					}
				}

				shouldGetConfig := atomic.CompareAndSwapInt32(&configNeeded, 1, 0)

				// Retry loop: воркер переподключается при ошибке
				attempt := 0
				for {
					if batchCtx.Err() != nil {
						return
					}

					getConf := shouldGetConfig && attempt == 0
					var cc chan<- string
					if getConf && !configSent {
						cc = configCh
					}

					sessErr := RunSession(batchCtx, tp, peer, d, localPort, useUDP,
						getConf, cc, wid, creds, deviceID, password, stats)

					if sessErr != nil {
						if batchCtx.Err() != nil {
							return
						}
						errStr := sessErr.Error()

						// Дописываем понятные пояснения для типичных ошибок со стороны балансировщиков ВК
						errStrLower := strings.ToLower(errStr)
						if strings.Contains(errStrLower, "attribute not found") ||
							strings.Contains(errStrLower, "rate limit") ||
							strings.Contains(errStrLower, "flood control") ||
							strings.Contains(errStrLower, "ip mismatch") ||
							strings.Contains(errStrLower, "error 29") {
							errStr += " (ошибка со стороны ВК)"
						}

						// Фатальные ошибки — не ретраим
						if strings.Contains(errStr, "TURN квота") ||
							strings.Contains(errStr, "хеш мёртв") ||
							strings.Contains(errStr, "FATAL_AUTH") {
							log.Printf("[ВОРКЕР #%d] Фатальная ошибка: %s", wid, errStr)
							return
						}
						attempt++
						log.Printf("[ВОРКЕР #%d] Ошибка (попытка %d): %s", wid, attempt, errStr)
					}

					if batchCtx.Err() != nil {
						return
					}

					// Пауза перед ретраем с джиттером 5-15 сек
					retryDelay := time.Duration(5+rand.Intn(11)) * time.Second
					select {
					case <-time.After(retryDelay):
					case <-batchCtx.Done():
						return
					}
				}
			}(wid, workerDelay, doneCh)
		}

		if !configSent && atomic.LoadInt32(&configNeeded) == 0 {
			configSent = true
		}

		// Сохраняем батч для бесшовной ротации
		prevCancel = batchCancel
		prevDoneChs = doneChs

		// Ждём TTL
		select {
		case <-time.After(cycleDuration):
			log.Printf("[ГРУППА #%d] TTL %v истёк, ротация", groupID, cycleDuration)
		case <-ctx.Done():
			return
		}

		cycleNumber++
		if !configSent && atomic.LoadInt32(&configNeeded) == 0 {
			configSent = true
		}
	}
}

// ComputeGroupTiming вычисляет фазу запуска
func ComputeGroupTiming(groupIndex int) (initialDelay, cycle time.Duration) {
	phase := time.Duration(groupIndex*phaseStepSec) * time.Second
	return phase, time.Duration(cycleSecs) * time.Second
}

// ValidateSchedule проверяет расписание
func ValidateSchedule(numGroups int) {
	maxPhase := (numGroups - 1) * phaseStepSec
	if maxPhase >= cycleSecs {
		log.Printf("⚠ Фазовый сдвиг последней группы (%dс) >= цикла (%dс)", maxPhase, cycleSecs)
	}
	log.Printf("Расписание: %d групп, цикл=%dс (%dмин), сдвиг=%dс",
		numGroups, cycleSecs, cycleSecs/60, phaseStepSec)
}

func phaseDuration(secs int) time.Duration {
	return time.Duration(secs) * time.Second
}

// ParseHashes — парсит строку хешей
func ParseHashes(raw string) []string {
	var result []string
	for _, h := range strings.Split(raw, ",") {
		h = strings.TrimSpace(h)
		if idx := strings.IndexAny(h, "/?#"); idx != -1 {
			h = h[:idx]
		}
		if h != "" {
			result = append(result, h)
		}
	}
	return result
}

// TurnParams — конфигурация TURN
type TurnParams struct {
	Host          string
	Port          string
	Hashes        []string
	SecondaryHash string
	Sni           string
}

// Unused import suppressor
var _ = fmt.Sprintf
