package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"
)

var firstNames = []string{
	"Александр", "Дмитрий", "Максим", "Сергей", "Андрей", "Алексей", "Артём", "Илья",
	"Кирилл", "Михаил", "Никита", "Матвей", "Роман", "Егор", "Арсений", "Иван",
	"Денис", "Даниил", "Тимофей", "Владислав", "Павел", "Руслан", "Марк", "Тимур",
	"Олег", "Виктор", "Юрий", "Николай", "Антон", "Владимир", "Григорий", "Степан",
	"Фёдор", "Игнат", "Леонид", "Борис", "Георгий", "Валентин", "Артур", "Анатолий",
	"Анна", "Мария", "Елена", "Дарья", "Анастасия", "Екатерина", "Виктория", "Ольга",
	"Наталья", "Юлия", "Татьяна", "Светлана", "Ирина", "Ксения", "Алина", "Елизавета",
	"Полина", "Софья", "Маргарита", "Вероника", "Диана", "Валерия", "Кристина",
}

var lastNames = []string{
	"Иванов", "Смирнов", "Кузнецов", "Попов", "Васильев", "Петров", "Соколов", "Михайлов",
	"Новиков", "Федоров", "Морозов", "Волков", "Алексеев", "Лебедев", "Семенов", "Егоров",
	"Павлов", "Козлов", "Степанов", "Николаев", "Орлов", "Андреев", "Макаров", "Никитин",
	"Захаров", "Зайцев", "Соловьев", "Борисов", "Яковлев", "Григорьев", "Романов", "Воробьев",
	"Калинин", "Гусев", "Титов", "Белов", "Комаров", "Орлов", "Киселёв", "Макаров",
}

// BotProfile содержит уникальные данные для одного запроса/сессии
type BotProfile struct {
	UserAgent       string
	Name            string
	BrowserFP       string
	DeviceJSON      string
	CursorJSON      string
	Accelerometer   string
	Gyroscope       string
	Motion          string
	Taps            string
	Downlink        string
	DebugInfo       string
	BatteryLevel    string
	TouchSupport    string
	CanvasFP        string
	WebGLFP         string
	AudioFP         string
}

// generateDebugInfo создаёт СТАТИЧНЫЙ debug_info привязанный к устройству.
// Реальный браузер генерирует его один раз при загрузке страницы и НЕ меняет.
func generateDebugInfo(deviceID string) string {
	hash := sha256.Sum256([]byte(deviceID + "_debug_info_static_salt_v2"))
	return hex.EncodeToString(hash[:])
}

// GenerateBotProfile принимает РЕАЛЬНЫЙ User-Agent из Android
func GenerateBotProfile(realUserAgent, baseDeviceID string, actionSeed uint64) BotProfile {
	// 1. Генератор для ЖЕЛЕЗА (Hardware). Привязан к DeviceID — не меняется между запросами!
	hwHash := sha256.Sum256([]byte(baseDeviceID + "hardware_salt"))
	hwSeed := binary.BigEndian.Uint64(hwHash[:8])
	hwRng := rand.New(rand.NewSource(int64(hwSeed)))

	// 2. Генератор для ДЕЙСТВИЙ (Actions). Меняется каждый запрос.
	actionRng := rand.New(rand.NewSource(int64(actionSeed)))

	// --- 1. ГЕНЕРАЦИЯ ПОСТОЯННОГО ЖЕЛЕЗА ДЛЯ ЭТОГО УСТРОЙСТВА ---

	// Мобильные разрешения: вертикальные!
	wChoices := []int{720, 1080, 1440}
	w := wChoices[hwRng.Intn(len(wChoices))]

	// Соотношение сторон современных телефонов (от 16:9 до 21:9)
	ratio := 1.77 + hwRng.Float64()*0.56
	h := int(float64(w) * ratio)

	// Статус бар и навигационная панель отнимают место
	availW := w
	availH := h - (60 + hwRng.Intn(80))
	innerW := w
	innerH := availH - (hwRng.Intn(40))

	// Пиксельная плотность мобилок высокая
	dprChoices := []float64{2.0, 2.5, 2.75, 3.0, 3.5}
	dpr := dprChoices[hwRng.Intn(len(dprChoices))]

	// У телефонов почти всегда 8 ядер, реже 6 или 4. ОЗУ 4, 6, 8, 12.
	hwThreads := []int{4, 6, 8, 8, 8}[hwRng.Intn(5)]
	mem := []int{4, 6, 8, 12}[hwRng.Intn(4)]

	// timezoneOffset — Россия UTC+3 (для Москвы), но может быть и +2..+12
	tzOffsets := []int{-180, -120, -240, -300, -360, -420, -480, -540, -600, -660} // минуты
	tzOffset := tzOffsets[hwRng.Intn(len(tzOffsets))]

	deviceJSON := fmt.Sprintf(
		`{"screenWidth":%d,"screenHeight":%d,"screenAvailWidth":%d,"screenAvailHeight":%d,"innerWidth":%d,"innerHeight":%d,"devicePixelRatio":%g,"language":"ru-RU","languages":["ru-RU","en-US"],"webdriver":false,"hardwareConcurrency":%d,"deviceMemory":%d,"connectionEffectiveType":"4g","notificationsPermission":"%s","timezoneOffset":%d,"platform":"Linux aarch64","productSub":"20030107","vendor":"Google Inc."}`,
		w, h, availW, availH, innerW, innerH, dpr, hwThreads, mem,
		"default", tzOffset,
	)

	// Browser Fingerprint (уникальный хэш железа)
	browserFP := fmt.Sprintf("%016x%016x%016x%016x",
		hwRng.Uint64(), hwRng.Uint64(), hwRng.Uint64(), hwRng.Uint64())

	// Canvas fingerprint — СТАТИЧНЫЙ для устройства, как у реального браузера
	canvasFP := fmt.Sprintf("%08x", hwRng.Uint32())

	// WebGL fingerprint — статичный, зависит от GPU (Adreno, Mali)
	gpuChoices := []string{"Mali-G610", "Mali-G710", "Adreno (TM) 643", "Adreno (TM) 650", "Adreno (TM) 730", "Xclipse 920"}
	gpuName := gpuChoices[hwRng.Intn(len(gpuChoices))]
	webglFP := fmt.Sprintf("%s|%08x", gpuName, hwRng.Uint32())

	// Audio fingerprint — СТАТИЧНЫЙ для устройства (имитация AudioContext)
	audioFP := fmt.Sprintf("%.6f", 124.0+hwRng.Float64()*12.0)

	// Debug info — СТАТИЧНЫЙ, привязан к DeviceID
	debugInfo := generateDebugInfo(baseDeviceID)

	// Battery level — имитируем, что телефон заряжается (люди редко сидят с 5%)
	batteryLevel := 0.35 + hwRng.Float64()*0.65 // 35%..100%

	// Touch support — Android WebView ВСЕГДА поддерживает тач
	touchSupport := fmt.Sprintf(`{"maxTouchPoints":%d,"touchEvent":true,"touchStart":true}`, 5+hwRng.Intn(6))

	// --- 2. ГЕНЕРАЦИЯ УНИКАЛЬНЫХ ДЕЙСТВИЙ (Каждый запрос) ---

	// Имя (рандом каждый раз)
	fn := firstNames[actionRng.Intn(len(firstNames))]
	ln := lastNames[actionRng.Intn(len(lastNames))]
	var name string
	if actionRng.Float32() < 0.3 {
		name = fn
	} else {
		lastChar := fn[len(fn)-2:]
		if lastChar == "на" || lastChar == "ия" || lastChar == "да" || lastChar == "ра" {
			ln = ln + "а"
		}
		name = fn + " " + ln
	}

	// КУРСОР: Телефоны НЕ ИМЕЮТ КУРСОРА для VK. Пустой массив.
	cursor := "[]"

	// ТАПЫ (Прикосновения к экрану) — с timestamp и реалистичными паттернами
	taps := generateMobileTaps(actionRng, w, h)

	// СЕНСОРЫ: У телефонов они ВСЕГДА есть. Имитируем, что телефон держат в руке.
	// Реальный Android WebView шлёт данные акселерометра/гироскопа постоянно.
	accel, gyro, motion := generateMobileSensors(hwRng, actionRng)

	// Сеть: скачет в зависимости от качества связи, но НЕ хаотично
	dl := generateDownlink(actionRng)

	return BotProfile{
		UserAgent:       realUserAgent,
		Name:            name,
		BrowserFP:       browserFP,
		DeviceJSON:      deviceJSON,
		CursorJSON:      cursor,
		Accelerometer:   accel,
		Gyroscope:       gyro,
		Motion:          motion,
		Taps:            taps,
		Downlink:        dl,
		DebugInfo:       debugInfo,
		BatteryLevel:    fmt.Sprintf("%.2f", batteryLevel),
		TouchSupport:    touchSupport,
		CanvasFP:        canvasFP,
		WebGLFP:         webglFP,
		AudioFP:         audioFP,
	}
}

// generateMobileTaps генерирует реалистичные прикосновения с timestamp
// Реальный Android WebView отправляет: x, y, duration, И timestamp (мс от начала сессии)
func generateMobileTaps(rng *rand.Rand, width, height int) string {
	// Сценарии поведения человека:
	// 0: Человек просто открыл и смотрит (0 тапов)
	// 1: Один тап (проверить связь)
	// 2: 2-3 тапа (легкий скролл)
	// 3: 4-6 тапов (активное пользование)
	scenario := rng.Intn(10)
	var n int
	switch {
	case scenario < 2:
		n = 0 // 20% — ничего не трогает
	case scenario < 4:
		n = 1 // 20% — один тап
	case scenario < 7:
		n = 2 + rng.Intn(2) // 30% — 2-3 тапа
	default:
		n = 4 + rng.Intn(3) // 30% — 4-6 тапов
	}

	if n == 0 {
		return "[]"
	}

	taps := make([]string, n)
	// Timestamp начинается с 0 и растёт. Реальная сессия капчи ~3-8 секунд.
	// Первый тап происходит через 500-2000мс после загрузки (человек осматривается)
	baseTime := 500 + rng.Intn(1500)

	for i := 0; i < n; i++ {
		// Клик обычно в нижней/средней половине экрана (ближе к пальцу)
		tapX := float64(width) * (0.15 + rng.Float64()*0.7)
		tapY := float64(height) * (0.3 + rng.Float64()*0.6)

		// Длительность тапа: человек нажимает 50-200мс
		duration := 50 + rng.Intn(150)

		// Между тапами проходит 300-2000мс (человек не робот)
		if i > 0 {
			baseTime += 300 + rng.Intn(1700)
		}

		taps[i] = fmt.Sprintf(`{"x":%.1f,"y":%.1f,"duration":%d,"time":%d}`, tapX, tapY, duration, baseTime)
	}
	return "[" + strings.Join(taps, ",") + "]"
}

// generateMobileSensors генерирует данные акселерометра/гироскопа с реалистичным дрейфом
// Реальный телефон НЕ выдаёт случайные числа — есть гравитация, дрейф, тремор рук
func generateMobileSensors(hwRng, actionRng *rand.Rand) (string, string, string) {
	// Базовая ориентация телефона (статичная, от hwRng) — как человек держит телефон
	// Телефон обычно наклонён к лицу: Y≈4-7, Z≈7-10, X≈-1..1
	baseY := 4.0 + hwRng.Float64()*3.0
	baseZ := 8.0 + hwRng.Float64()*1.5
	baseX := -1.0 + hwRng.Float64()*2.0

	// Сколько сэмплов шлёт браузер за сессию? Обычно 1-5
	n := 1 + actionRng.Intn(5)

	accelEvents := make([]string, n)
	gyroEvents := make([]string, n)
	motionEvents := make([]string, n)

	// ДРЕЙФ: значения не скачут, они плавно меняются (инерция)
	prevAX, prevAY, prevAZ := baseX, baseY, baseZ
	prevGX, prevGY, prevGZ := 0.0, 0.0, 0.0

	for i := 0; i < n; i++ {
		// Акселерометр: гравитация + микро-тремор рук (±0.05 м/с²)
		// Тремор НЕ рандомный, а коррелированный (палец дрожит по всем осям)
		tremorX := actionRng.Float64()*0.1 - 0.05
		tremorY := actionRng.Float64()*0.1 - 0.05
		tremorZ := actionRng.Float64()*0.1 - 0.05

		// Плавный дрейф (инерция): новое значение близко к предыдущему
		drift := 0.3 // коэффициент инерции
		ax := prevAX*drift + baseX*(1-drift) + tremorX
		ay := prevAY*drift + baseY*(1-drift) + tremorY
		az := prevAZ*drift + baseZ*(1-drift) + tremorZ

		prevAX, prevAY, prevAZ = ax, ay, az

		accelEvents[i] = fmt.Sprintf(`{"x":%.3f,"y":%.3f,"z":%.3f}`, ax, ay, az)

		// Гироскоп: углы поворота (альфа, бета, гамма)
		// Телефон слегка покачивается в руке
		gx := prevGX*0.7 + (actionRng.Float64()*0.8-0.4)*0.3
		gy := prevGY*0.7 + (actionRng.Float64()*0.8-0.4)*0.3
		gz := prevGZ*0.7 + (actionRng.Float64()*0.8-0.4)*0.3
		prevGX, prevGY, prevGZ = gx, gy, gz

		gyroEvents[i] = fmt.Sprintf(`{"alpha":%.2f,"beta":%.2f,"gamma":%.2f}`, gx, gy, gz)

		// Motion: accelerationIncludingGravity (обёртка для акселерометра)
		motionEvents[i] = fmt.Sprintf(`{"accelerationIncludingGravity":{"x":%.3f,"y":%.3f,"z":%.3f}}`, ax, ay, az)
	}

	return "[" + strings.Join(accelEvents, ",") + "]",
		"[" + strings.Join(gyroEvents, ",") + "]",
		"[" + strings.Join(motionEvents, ",") + "]"
}

// generateDownlink имитирует Network Information API
// Реальный 4G/LTE на телефоне: значение стабильное, меняется раз в несколько секунд
func generateDownlink(rng *rand.Rand) string {
	// Сценарий: сколько раз браузер запрашивает downlink за сессию
	// Chrome обычно шлёт 7-16 раз с интервалом ~200-500мс
	n := 7 + rng.Intn(10)

	// Базовая скорость: реальный 4G в России 8-30 Мбит/с
	// 5G: 50-200 Мбит/с, 3G: 1-5 Мбит/с
	// Выбираем реалистичный 4G
	baseDL := 10.0 + rng.Float64()*20.0 // 10..30 Мбит/с

	if n == 1 {
		return fmt.Sprintf("[%.1f]", baseDL)
	}

	vals := make([]string, n)

	// Реальный downlink: первые 2-3 значения могут немного отличаться,
	// потом стабилизируется (браузер кэширует)
	stabilizeAfter := 2 + rng.Intn(3)

	for i := 0; i < n; i++ {
		var variation float64
		if i < stabilizeAfter {
			// Начальные измерения могут "скакать" (браузер определяет)
			variation = baseDL * (0.85 + rng.Float64()*0.3) // ±15%
		} else {
			// Стабильное значение (кэш браузера)
			variation = baseDL * (0.98 + rng.Float64()*0.04) // ±2%
		}
		vals[i] = fmt.Sprintf("%.1f", variation)
	}
	return "[" + strings.Join(vals, ",") + "]"
}

// GenerateCaptchaCursor генерирует курсор для десктопной капчи (если VK показал десктоп-капчу)
// Имитирует движение мыши к чекбоксу "Я не робот"
func GenerateCaptchaCursor(rng *rand.Rand) string {
	// Начальная позиция (человек двигает мышь из угла/середины экрана)
	startX := 200 + rng.Float64()*1520
	startY := 200 + rng.Float64()*680

	// Цель: чекбокс "Я не робот" примерно в центре окна капчи
	// Окно капчи ~400x400 в центре экрана 1920x1080
	targetX := 960.0 + (rng.Float64()-0.5)*200
	targetY := 540.0 + (rng.Float64()-0.5)*100 + 30 // +30px ниже (кнопка)

	// Контрольные точки для кривой Безье (имитация дугового движения руки)
	cp1x := startX + (rng.Float64()-0.5)*500
	cp1y := startY + (rng.Float64()-0.5)*300
	cp2x := targetX + (rng.Float64()-0.5)*150
	cp2y := targetY + (rng.Float64()-0.5)*80

	// 6-12 точек (плавное движение)
	np := 6 + rng.Intn(7)
	points := make([]string, np)

	for i := 0; i < np; i++ {
		t := float64(i) / float64(np-1)
		mt := 1 - t

		// Кубическая кривая Безье
		x := mt*mt*mt*startX + 3*mt*mt*t*cp1x + 3*mt*t*t*cp2x + t*t*t*targetX
		y := mt*mt*mt*startY + 3*mt*mt*t*cp1y + 3*mt*t*t*cp2y + t*t*t*targetY

		// Микро-шум (рука дрожит ±1.5px)
		x += rng.Float64()*3 - 1.5
		y += rng.Float64()*3 - 1.5

		points[i] = fmt.Sprintf(`{"x":%.1f,"y":%.1f}`, x, y)
	}
	return "[" + strings.Join(points, ",") + "]"
}

// SimulateHumanDelay имитирует задержку "человек думает"
// Используется между шагами капчи
func SimulateHumanDelay(rng *rand.Rand, action string) {
	var delayMs int
	switch action {
	case "page_load":
		// Загрузка страницы: 1.5-3.5с (как реальный WebView)
		delayMs = 1500 + rng.Intn(2000)
	case "read_captcha":
		// Человек осматривает капчу: 0.8-2.5с
		delayMs = 800 + rng.Intn(1700)
	case "move_mouse":
		// Движение мыши к чекбоксу: 0.3-0.9с
		delayMs = 300 + rng.Intn(600)
	case "click_checkbox":
		// Пауза перед кликом "Я не робот": 0.2-0.6с
		delayMs = 200 + rng.Intn(400)
	case "wait_for_check":
		// Ожидание проверки капчи: 1.5-4с
		delayMs = 1500 + rng.Intn(2500)
	case "between_steps":
		// Между шагами API: 0.1-0.4с
		delayMs = 100 + rng.Intn(300)
	default:
		delayMs = 200 + rng.Intn(400)
	}

	// Добавляем джиттер ±10%
	jitter := int(float64(delayMs) * (0.9 + rng.Float64()*0.2))
	time.Sleep(time.Duration(jitter) * time.Millisecond)
}

// CaptchaSessionTiming хранит все тайминги одной сессии капчи
type CaptchaSessionTiming struct {
	// Время загрузки страницы капчи (fetch POW)
	FetchPowMs int
	// Время "чтения" капчи человеком перед действиями
	ReadCaptchaMs int
	// Пауза между settings и componentDone
	SettingsToComponentMs int
	// Пауза между componentDone и check (движение мыши + клик)
	ComponentToCheckMs int
	// Пауза после check перед endSession
	CheckToEndMs int
	// Пауза для endSession
	EndSessionMs int
	// Дополнительный "человеческий" фактор — иногда человек "зависает"
	ExtraPauseMs int
}

// GenerateCaptchaTiming генерирует РЕАЛИСТИЧНЫЕ тайминги для ОДНОЙ сессии капчи
// Общее время: 5-10 секунд (как реальный человек)
// Каждый шаг имеет динамическую вариацию ±100мс
func GenerateCaptchaTiming(rng *rand.Rand) CaptchaSessionTiming {
	// Базовые диапазоны для каждого шага
	// Реальный человек: загрузка → осмотр → движение мыши → клик → ожидание
	
	// 1. Загрузка страницы (POW fetch)
	// Браузер загружает HTML, парсит, исполняет JS
	fetchPow := 600 + rng.Intn(800) // 0.6-1.4с
	
	// 2. Человек "осматривает" страницу капчи
	// Прочитал текст, понял что нужно сделать
	readCaptcha := 700 + rng.Intn(1200) // 0.7-1.9с
	
	// 3. settings → componentDone
	// Человек начинает взаимодействовать (движение мыши)
	settingsToComponent := 800 + rng.Intn(1200) // 0.8-2.0с
	
	// 4. componentDone → check (САМЫЙ ВАЖНЫЙ ШАГ!)
	// Здесь человек двигает мышь к чекбоксу и кликает
	// VK смотрит на ЭТОТ промежуток особенно внимательно
	// Реальное время: 1.5-3.5с (движение + пауза перед кликом + клик)
	componentToCheck := 1500 + rng.Intn(2000) // 1.5-3.5с
	
	// 5. check → endSession
	// Ожидание результата проверки
	checkToEnd := 400 + rng.Intn(800) // 0.4-1.2с
	
	// 6. endSession
	endSession := 100 + rng.Intn(200) // 0.1-0.3с
	
	// 7. Дополнительная "человеческая" пауза
	// Иногда человек "зависает" на секунду-другую (10% шанс)
	var extraPause int
	if rng.Float32() < 0.10 {
		extraPause = 800 + rng.Intn(1500) // 0.8-2.3с дополнительная пауза
	}
	
	// Проверяем общее время (должно быть 5-10 секунд)
	total := fetchPow + readCaptcha + settingsToComponent + componentToCheck + checkToEnd + endSession + extraPause
	
	// Если общее время < 5000мс — добавляем недостающее
	if total < 5000 {
		deficit := 5000 - total + rng.Intn(1000) // +0-1с сверху для запаса
		// Распределяем добавку по шагам (больше всего в componentToCheck)
		componentToCheck += deficit * 40 / 100
		settingsToComponent += deficit * 25 / 100
		readCaptcha += deficit * 20 / 100
		checkToEnd += deficit * 15 / 100
	}
	
	// Если общее время > 10000мс — уменьшаем
	if total > 10000 {
		excess := total - 10000
		componentToCheck -= excess * 40 / 100
		settingsToComponent -= excess * 25 / 100
		readCaptcha -= excess * 20 / 100
		checkToEnd -= excess * 15 / 100
		
		// Гарантируем минимумы
		if componentToCheck < 1200 { componentToCheck = 1200 }
		if settingsToComponent < 600 { settingsToComponent = 600 }
		if readCaptcha < 500 { readCaptcha = 500 }
		if checkToEnd < 300 { checkToEnd = 300 }
	}
	
	return CaptchaSessionTiming{
		FetchPowMs:          fetchPow,
		ReadCaptchaMs:       readCaptcha,
		SettingsToComponentMs: settingsToComponent,
		ComponentToCheckMs:  componentToCheck,
		CheckToEndMs:        checkToEnd,
		EndSessionMs:        endSession,
		ExtraPauseMs:        extraPause,
	}
}

// GetCaptchaFieldForDeviceJSON возвращает device JSON для конкретного сценария
// Для десктопной капчи — десктопный профиль, для мобильной — мобильный
func GetCaptchaDeviceJSON(isMobile bool, rng *rand.Rand) string {
	if isMobile {
		w := []int{720, 1080}[rng.Intn(2)]
		h := int(float64(w) * (1.77 + rng.Float64()*0.56))
		return fmt.Sprintf(
			`{"screenWidth":%d,"screenHeight":%d,"screenAvailWidth":%d,"screenAvailHeight":%d,"innerWidth":%d,"innerHeight":%d,"devicePixelRatio":%.1f,"language":"ru-RU","languages":["ru-RU","en-US"],"webdriver":false,"hardwareConcurrency":8,"deviceMemory":6,"connectionEffectiveType":"4g","notificationsPermission":"default"}`,
			w, h, w, h-80, w, h-120, 3.0,
		)
	}
	// Десктоп (как в HAR-захвате)
	return `{"screenWidth":1920,"screenHeight":1080,"screenAvailWidth":1920,"screenAvailHeight":1032,"innerWidth":1920,"innerHeight":945,"devicePixelRatio":1,"language":"en-US","languages":["en-US"],"webdriver":false,"hardwareConcurrency":16,"deviceMemory":8,"connectionEffectiveType":"4g","notificationsPermission":"denied"}`
}

// GenerateCaptchaDownlink генерирует downlink для капчи (десктопный стиль)
// HAR показывает: браузер повторяет одно значение N раз
func GenerateCaptchaDownlink(rng *rand.Rand) string {
	n := 8 + rng.Intn(9) // 8..16 значений
	// WiFi/Ethernet: 50-200 Мбит/с, 4G: 10-30
	baseDL := 50.0 + rng.Float64()*150.0

	vals := make([]string, n)
	// Первые 2-3 могут отличаться, потом стабилизируется
	stab := 2 + rng.Intn(2)
	for i := 0; i < n; i++ {
		var v float64
		if i < stab {
			v = baseDL * (0.9 + rng.Float64()*0.2)
		} else {
			v = baseDL * (0.99 + rng.Float64()*0.02)
		}
		vals[i] = fmt.Sprintf("%.1f", v)
	}
	return "[" + strings.Join(vals, ",") + "]"
}

// GenerateCaptchaAccelerometer для десктопной капчи (пустой или минимальный)
// Десктоп НЕ имеет акселерометр — отправляем []
func GenerateCaptchaAccelerometer() string {
	return "[]"
}

// GenerateCaptchaGyroscope для десктопной капчи
func GenerateCaptchaGyroscope() string {
	return "[]"
}

// GenerateCaptchaMotion для десктопной капчи
func GenerateCaptchaMotion() string {
	return "[]"
}

// GenerateCaptchaTaps для десктопной капчи (пусто — нет тачскрина)
func GenerateCaptchaTaps() string {
	return "[]"
}

// GenerateCaptchaConnectionRtt для десктопной капчи
// Реальный RTT для WiFi: 2-15мс
func GenerateCaptchaConnectionRtt(rng *rand.Rand) string {
	n := 7 + rng.Intn(5)
	baseRTT := 3.0 + rng.Float64()*12.0
	vals := make([]string, n)
	for i := 0; i < n; i++ {
		vals[i] = fmt.Sprintf("%.1f", baseRTT*(0.9+rng.Float64()*0.2))
	}
	return "[" + strings.Join(vals, ",") + "]"
}

// GenerateCanvasFingerprint имитирует Canvas fingerprint
// Реальный браузер рендерит canvas и хэширует — результат СТАТИЧНЫЙ для GPU+драйвера
func GenerateCanvasFingerprint(deviceID string) string {
	hash := sha256.Sum256([]byte(deviceID + "_canvas_fp"))
	// Возвращаем первые 8 символов (как realse Canvas fingerprint)
	return hex.EncodeToString(hash[:4])
}

// GaussianRand генерирует нормально распределённое случайное число
// (Box-Muller transform) — более реалистично для человеческого поведения
func GaussianRand(rng *rand.Rand, mean, stddev float64) float64 {
	u1 := rng.Float64()
	u2 := rng.Float64()
	// Box-Muller
	z := math.Sqrt(-2.0*math.Log(u1)) * math.Cos(2.0*math.Pi*u2)
	return mean + stddev*z
}
