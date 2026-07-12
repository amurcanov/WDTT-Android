package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var CaptchaResultChan = make(chan string, 1)

var captchaModeValue atomic.Value
var vkAuthModeValue atomic.Value

func init() {
	captchaModeValue.Store("auto")
	vkAuthModeValue.Store("vkcalls")
}

func normalizeCaptchaMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "auto", "rjs", "wv":
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return "auto"
	}
}

func setCaptchaMode(mode string) string {
	normalized := normalizeCaptchaMode(mode)
	captchaModeValue.Store(normalized)
	return normalized
}

func getCaptchaMode() string {
	mode, _ := captchaModeValue.Load().(string)
	if mode == "" {
		return "auto"
	}
	return mode
}

func normalizeVKAuthMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "legacy":
		return "legacy"
	default:
		return "vkcalls"
	}
}

func setVKAuthMode(mode string) string {
	normalized := normalizeVKAuthMode(mode)
	vkAuthModeValue.Store(normalized)
	return normalized
}

func getVKAuthMode() string {
	mode, _ := vkAuthModeValue.Load().(string)
	if mode == "" {
		return "vkcalls"
	}
	return mode
}

func drainCaptchaResult() {
	select {
	case <-CaptchaResultChan:
	default:
	}
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	setupGlobalResolver()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		select {
		case s := <-sig:
			log.Printf("[КЛИЕНТ] Сигнал %v, завершаю...", s)
			cancel()
		case <-ctx.Done():
			return
		}
		select {
		case s := <-sig:
			log.Printf("[КЛИЕНТ] Повторный %v, принудительный выход", s)
			os.Exit(1)
		case <-ctx.Done():
		}
	}()

	var pauseFlag int32

	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if !strings.Contains(line, "error:tunnel stopped") {
				log.Printf("[STDIN] %s", line)
			}
			switch {
			case line == "PAUSE":
				atomic.StoreInt32(&pauseFlag, 1)
			case line == "RESUME":
				atomic.StoreInt32(&pauseFlag, 0)
			case line == "STOP":
				cancel()
				return
			case strings.HasPrefix(line, "CAPTCHA_RESULT|"):
				result := strings.TrimPrefix(line, "CAPTCHA_RESULT|")
				drainCaptchaResult()
				CaptchaResultChan <- result
				log.Printf("[КАПЧА] Результат от Kotlin записан в канал")
			}
		}
	}()

	ppid := os.Getppid()
	go func() {
		for {
			time.Sleep(2 * time.Second)
			if os.Getppid() != ppid {
				os.Exit(0)
			}
		}
	}()

	host := flag.String("turn", "", "переопределить IP TURN")
	port := flag.String("port", "", "переопределить порт TURN")
	listen := flag.String("listen", "127.0.0.1:9000", "локальный адрес")
	vkHash := flag.String("vk", "", "хеши VK-звонков (через запятую)")
	peerAddr := flag.String("peer", "", "адрес:порт VPS сервера")
	numW := flag.Int("n", 24, "количество воркеров (кратно 12)")

	deviceID := flag.String("device-id", "unknown", "уникальный ID устройства")
	connPassword := flag.String("password", "", "пароль подключения")
	vkAuthMode := flag.String("vk-auth-mode", "vkcalls", "режим получения VK TURN-кредов (vkcalls/legacy)")
	captchaMode := flag.String("captcha-mode", "auto", "режим обхода капчи (auto/wv/rjs)")
	fingerprint := flag.String("fingerprint", "chrome", "браузерный фингерпринт (chrome, safari, ios, android, firefox)")
	clientIdsFlag := flag.String("client-ids", "", "ID клиентов VK через запятую")
	obfsMode := flag.String("obfs", "audio", "режим обфускации (audio/video)")
	useWrapS := flag.Bool("wrap-s", false, "SRTP-WRAP-S для free-turn-proxy")
	freeObfProfile := flag.String("obf-profile", freeProfileOpus3, "free-turn OBF profile")
	freeObfKey := flag.String("obf-key", "", "free-turn OBF key (64 hex chars)")
	freeClientID := flag.String("free-client-id", "", "free-turn Client ID")

	flag.Parse()
	activeVKAuthMode := setVKAuthMode(*vkAuthMode)
	activeCaptchaMode := setCaptchaMode(*captchaMode)

	if *peerAddr == "" || *vkHash == "" {
		log.Fatal("[КЛИЕНТ] Нужны -peer и -vk")
	}

	cleanPeerAddr := strings.TrimSpace(*peerAddr)
	var err error
	var peer *net.UDPAddr
	for i := 0; i < 15; i++ {
		peer, err = net.ResolveUDPAddr("udp", cleanPeerAddr)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if err != nil {
		log.Fatalf("[КЛИЕНТ] Ошибка разбора пира: %v", err)
	}

	if *fingerprint != "" {
		SetActiveFingerprint(*fingerprint)
	}
	if *clientIdsFlag != "" {
		SetActiveClientIds(*clientIdsFlag)
	}

	hashes := ParseHashes(*vkHash)
	if len(hashes) == 0 {
		log.Fatal("[КЛИЕНТ] Нет хешей VK")
	}

	var wrapKey []byte
	if *useWrapS {
		if *freeClientID == "" {
			log.Fatal("[КЛИЕНТ] Для SRTP-WRAP-S нужен -free-client-id")
		}
		if *freeObfProfile != freeProfileOpus && *freeObfProfile != freeProfileOpus2 && *freeObfProfile != freeProfileOpus3 {
			log.Fatalf("[КЛИЕНТ] Неизвестный OBF profile: %s", *freeObfProfile)
		}
		wrapKey, err = hex.DecodeString(strings.TrimSpace(*freeObfKey))
		if err != nil || len(wrapKey) != wrapKeyLen {
			log.Fatal("[КЛИЕНТ] Для SRTP-WRAP-S нужен -obf-key из 64 hex символов")
		}
	} else {
		if *connPassword == "" {
			log.Fatal("[КЛИЕНТ] Нужен -password: WRAP ключ теперь выводится из пароля подключения")
		}
		wrapKey, err = deriveWrapKey(*connPassword)
		if err != nil {
			log.Fatalf("[КЛИЕНТ] WRAP key derive: %v", err)
		}
	}

	maxWorkers := 108
	if *numW > maxWorkers {
		*numW = maxWorkers
	}
	if *numW < workersPerGroup {
		*numW = workersPerGroup
	}
	*numW = (*numW / workersPerGroup) * workersPerGroup

	tp := &TurnParams{
		Host:     *host,
		Port:     *port,
		Hashes:   hashes,
		WrapKey:  wrapKey,
		ObfsMode: *obfsMode,
		UseWrapS: *useWrapS,
		ObfProfile: *freeObfProfile,
		ClientID: *freeClientID,
	}

	var localConn net.PacketConn
	actualListenAddr := *listen
	for i := 0; i < 5; i++ {
		localConn, err = net.ListenPacket("udp", actualListenAddr)
		if err == nil {
			break
		}
		log.Printf("[ОЖИДАНИЕ] Порт %s занят (возможно, старый процесс завершается). Жду... (%d/5)", actualListenAddr, i+1)
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		log.Printf("[АВТО-ПОРТ] Порт %s всё ещё занят. Пробую случайный динамический порт...", actualListenAddr)
		actualListenAddr = "127.0.0.1:0"
		localConn, err = net.ListenPacket("udp", actualListenAddr)
		if err != nil {
			log.Fatalf("[ФАТАЛ] Ошибка бинда динамического порта: %v", err)
		}
	}
	if uc, ok := localConn.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(socketBufSize)
		_ = uc.SetWriteBuffer(socketBufSize)
	}
	stopLocalConn := context.AfterFunc(ctx, func() { _ = localConn.Close() })
	defer stopLocalConn()

	_, localPort, _ := net.SplitHostPort(localConn.LocalAddr().String())
	if localPort == "" {
		localPort = "9000"
	}

	numGroups := *numW / workersPerGroup

	wrapStatus := "OFF"
	if *useWrapS {
		wrapStatus = fmt.Sprintf("SRTP-WRAP-S (%s, Client ID %s)", *freeObfProfile, *freeClientID)
	} else if len(wrapKey) == wrapKeyLen {
		wrapStatus = "ON (password HKDF + RTP AEAD)"
	}

	captchaStatus := "AUTO: Go v2 x2 -> WBV Auto x2 -> Go v2 x1 -> Manual WBV"
	switch activeCaptchaMode {
	case "wv":
		captchaStatus = "WBV selected in Android"
	case "rjs":
		captchaStatus = "RJS Go v2 with WBV Auto fallback"
	}

	log.Println("[КЛИЕНТ] ═══════════════════════════════════════")
	log.Printf("[КЛИЕНТ] VK Creds: Client IDs: %s", GetActiveClientIdsString())
	log.Printf("[КЛИЕНТ] VK Auth: %s", activeVKAuthMode)
	log.Printf("[КЛИЕНТ] TLS: %s fingerprint", GetActiveFingerprint())
	log.Printf("[КЛИЕНТ] Воркеров: %d (групп: %d, по %d)", *numW, numGroups, workersPerGroup)
	log.Printf("[КЛИЕНТ] Хешей: %d", len(hashes))
	log.Printf("[КЛИЕНТ] Слушаю: %s | Пир: %s", *listen, cleanPeerAddr)
	log.Printf("[КЛИЕНТ] Протокол: UDP")
	log.Printf("[КЛИЕНТ] WRAP: %s", wrapStatus)
	if *useWrapS {
		log.Printf("[WRAP-S] Free Turn profile=%s, Client ID активен", *freeObfProfile)
	} else {
		log.Printf("[WRAP] Ключ выведен из пароля, режим RTP AEAD активен")
	}
	log.Printf("[КЛИЕНТ] Device ID: %s", *deviceID)
	log.Printf("[КЛИЕНТ] Captcha: %s", captchaStatus)
	log.Println("[КЛИЕНТ] ═══════════════════════════════════════")

	stats := NewStats()
	shutdownCh := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(shutdownCh)
	}()
	go stats.RunLoop(shutdownCh)

	disp := NewDispatcher(ctx, localConn, stats)
	defer disp.Shutdown()

	configCh := make(chan string, 1)
	configDone := make(chan struct{})
	go func() {
		defer close(configDone)
		select {
		case rawConf, ok := <-configCh:
			if !ok || rawConf == "" {
				return
			}
			finalConf := rawConf
			if !strings.Contains(finalConf, "MTU =") {
				lines := strings.Split(finalConf, "\n")
				var newLines []string
				for _, line := range lines {
					newLines = append(newLines, line)
					if strings.TrimSpace(line) == "[Interface]" {
						newLines = append(newLines, "MTU = 1280")
					}
				}
				finalConf = strings.Join(newLines, "\n")
			}
			fmt.Println()
			fmt.Println("╔══════════════ WireGuard Конфиг ══════════════╗")
			for _, line := range strings.Split(finalConf, "\n") {
				fmt.Printf("║ %-44s ║\n", line)
			}
			fmt.Println("╚══════════════════════════════════════════════╝")
			if err := os.WriteFile("wg-turn.conf", []byte(finalConf+"\n"), 0600); err != nil {
				log.Printf("[КОНФИГ] Ошибка сохранения: %v", err)
			} else {
				log.Println("[КОНФИГ] Сохранён в wg-turn.conf")
			}
			emitConfig(finalConf)
		case <-ctx.Done():
		}
	}()

	var wg sync.WaitGroup
	workerIDCounter := 1

	var prevWaitCreds <-chan struct{}
	var prevWaitSpawn <-chan struct{}

	for g := 0; g < numGroups; g++ {
		isFirst := (g == 0)

		var myWaitCreds <-chan struct{}
		var mySignalCreds chan<- struct{}
		var myWaitSpawn <-chan struct{}
		var mySignalSpawn chan<- struct{}

		if g > 0 {
			myWaitCreds = prevWaitCreds
			myWaitSpawn = prevWaitSpawn
		}
		if g < numGroups-1 {
			chC := make(chan struct{})
			mySignalCreds = chC
			prevWaitCreds = chC

			chS := make(chan struct{})
			mySignalSpawn = chS
			prevWaitSpawn = chS
		}

		ids := make([]int, workersPerGroup)
		for i := range ids {
			ids[i] = workerIDCounter
			workerIDCounter++
		}

		gID := g + 1
		var cc chan<- string
		if isFirst {
			cc = configCh
		}

		wg.Add(1)
		go func(groupID int, isFirstGroup bool, configChan chan<- string, workerIds []int, startHashIndex int, waitC, waitS <-chan struct{}, sigC, sigS chan<- struct{}) {
			defer wg.Done()
			WorkerGroup(ctx, groupID, startHashIndex, tp, peer, disp, localPort,
				isFirstGroup && !*useWrapS, configChan, workerIds, &pauseFlag, *deviceID, *connPassword, stats, waitC, sigC, waitS, sigS)
		}(gID, isFirst, cc, ids, g, myWaitCreds, myWaitSpawn, mySignalCreds, mySignalSpawn)
	}

	wg.Wait()
	close(configCh)
	<-configDone
	log.Println("[КЛИЕНТ] Все воркеры завершены")
}
