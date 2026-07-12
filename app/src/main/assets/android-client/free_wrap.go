package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	freeProfileOpus  = "rtpopus"
	freeProfileOpus2 = "rtpopus2"
	freeProfileOpus3 = "rtpopus3"
	freeRtpPayload   = 0x6f
)

type freeWrapCodec interface {
	WrapInto(dst, payload []byte) (int, error)
	UnwrapPacket(wire, dst []byte) (int, error)
	Overhead() int
}

func newFreeWrapCodec(profile string, key []byte) (freeWrapCodec, error) {
	switch profile {
	case freeProfileOpus:
		return newFreeWrap1(key)
	case freeProfileOpus2:
		return newFreeWrap2(key)
	case freeProfileOpus3:
		return newFreeWrap3(key)
	default:
		return nil, fmt.Errorf("free wrap: unknown obf profile %q", profile)
	}
}

func writeFreeTurnClientID(conn net.Conn, clientID string) error {
	b := []byte(clientID)
	if len(b) > 255 {
		b = b[:255]
	}
	record := make([]byte, len(b)+1)
	record[0] = byte(len(b))
	copy(record[1:], b)
	_, err := conn.Write(record)
	return err
}

// rtpopus: RTP header + explicit nonce + ChaCha20-Poly1305 tag.
type freeWrap1 struct {
	aead      cipher.AEAD
	sessionID [4]byte
	ssrc      [4]byte
	counter   atomic.Uint64
	seq       atomic.Uint32
	timestamp atomic.Uint32
}

func newFreeWrap1(key []byte) (*freeWrap1, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("free wrap: key must be %d bytes", wrapKeyLen)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	w := &freeWrap1{aead: aead}
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	copy(w.sessionID[:], random[0:4])
	copy(w.ssrc[:], random[4:8])
	w.sessionID[0] &^= 0x80
	w.ssrc[0] &^= 0x80
	w.seq.Store(uint32(binary.BigEndian.Uint16(random[8:10])))
	w.timestamp.Store(binary.BigEndian.Uint32(random[10:14]))
	w.counter.Store(binary.BigEndian.Uint64(random[16:24]))
	return w, nil
}

func (w *freeWrap1) Overhead() int { return 40 }

func (w *freeWrap1) WrapInto(dst, payload []byte) (int, error) {
	const headerLen = 24
	wireLen := len(payload) + w.Overhead()
	if len(dst) < wireLen {
		return 0, errors.New("free wrap: dst too small")
	}
	dst[0], dst[1] = 0x80, freeRtpPayload
	seq := uint16(w.seq.Add(1) - 1)
	binary.BigEndian.PutUint16(dst[2:4], seq)
	ts := w.timestamp.Add(960) - 960
	binary.BigEndian.PutUint32(dst[4:8], ts)
	copy(dst[8:12], w.ssrc[:])
	copy(dst[12:16], w.sessionID[:])
	binary.BigEndian.PutUint64(dst[16:24], w.counter.Add(1)-1)
	copy(dst[headerLen:], payload)
	w.aead.Seal(dst[headerLen:headerLen], dst[12:24], dst[headerLen:headerLen+len(payload)], dst[:headerLen])
	return wireLen, nil
}

func (w *freeWrap1) UnwrapPacket(wire, dst []byte) (int, error) {
	if len(wire) < w.Overhead() {
		return 0, errors.New("free wrap: packet too short")
	}
	plain, err := w.aead.Open(nil, wire[12:24], wire[24:], wire[:24])
	if err != nil {
		return 0, err
	}
	if len(plain) > len(dst) {
		return 0, errors.New("free wrap: dst too small")
	}
	copy(dst, plain)
	return len(plain), nil
}

// rtpopus2: RTP one-byte extension + explicit nonce.
type freeWrap2 struct {
	aead      cipher.AEAD
	sessionID [4]byte
	ssrc      [4]byte
	counter   atomic.Uint64
	seq       atomic.Uint32
	timestamp atomic.Uint32
	tcc       atomic.Uint32
	first     atomic.Bool
}

func newFreeWrap2(key []byte) (*freeWrap2, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("free wrap2: key must be %d bytes", wrapKeyLen)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	w := &freeWrap2{aead: aead}
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	copy(w.sessionID[:], random[0:4])
	copy(w.ssrc[:], random[4:8])
	w.sessionID[0] &^= 0x80
	w.seq.Store(uint32(binary.BigEndian.Uint16(random[8:10])))
	w.timestamp.Store(binary.BigEndian.Uint32(random[10:14]))
	w.tcc.Store(uint32(binary.BigEndian.Uint16(random[14:16])))
	w.counter.Store(binary.BigEndian.Uint64(random[16:24]))
	return w, nil
}

func (w *freeWrap2) Overhead() int { return 52 }

func (w *freeWrap2) WrapInto(dst, payload []byte) (int, error) {
	const headerLen = 36
	wireLen := len(payload) + w.Overhead()
	if len(dst) < wireLen {
		return 0, errors.New("free wrap2: dst too small")
	}
	dst[0] = 0x90
	pt := byte(freeRtpPayload)
	if w.first.CompareAndSwap(false, true) {
		pt |= 0x80
	}
	dst[1] = pt
	seq := uint16(w.seq.Add(1) - 1)
	binary.BigEndian.PutUint16(dst[2:4], seq)
	binary.BigEndian.PutUint32(dst[4:8], w.timestamp.Add(960)-960)
	copy(dst[8:12], w.ssrc[:])
	dst[12], dst[13] = 0xbe, 0xde
	binary.BigEndian.PutUint16(dst[14:16], 2)
	dst[16], dst[17] = 0x10, 0x80|byte(seq&0x3f)
	dst[18] = 0x21
	binary.BigEndian.PutUint16(dst[19:21], uint16(w.tcc.Add(1)-1))
	dst[21], dst[22], dst[23] = 0, 0, 0
	copy(dst[24:28], w.sessionID[:])
	binary.BigEndian.PutUint64(dst[28:36], w.counter.Add(1)-1)
	copy(dst[headerLen:], payload)
	w.aead.Seal(dst[headerLen:headerLen], dst[24:36], dst[headerLen:headerLen+len(payload)], dst[:headerLen])
	return wireLen, nil
}

func (w *freeWrap2) UnwrapPacket(wire, dst []byte) (int, error) {
	if len(wire) < w.Overhead() {
		return 0, errors.New("free wrap2: packet too short")
	}
	plain, err := w.aead.Open(nil, wire[24:36], wire[36:], wire[:36])
	if err != nil {
		return 0, err
	}
	if len(plain) > len(dst) {
		return 0, errors.New("free wrap2: dst too small")
	}
	copy(dst, plain)
	return len(plain), nil
}

// rtpopus3 extends rtpopus2 with abs-send-time and voice-like pacing fields.
type freeWrap3 struct {
	aead      cipher.AEAD
	sessionID [4]byte
	ssrc      [4]byte
	start     time.Time
	mu        sync.Mutex
	counter   uint64
	seq       uint16
	timestamp uint32
	tcc       uint16
	speech    bool
	stateLeft int
	gapLeft   int
	gapSize   int
}

func newFreeWrap3(key []byte) (*freeWrap3, error) {
	if len(key) != wrapKeyLen {
		return nil, fmt.Errorf("free wrap3: key must be %d bytes", wrapKeyLen)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	var random [24]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	w := &freeWrap3{aead: aead, start: time.Now(), speech: true}
	copy(w.sessionID[:], random[0:4])
	copy(w.ssrc[:], random[4:8])
	w.sessionID[0] &^= 0x80
	w.seq = binary.BigEndian.Uint16(random[8:10])
	w.timestamp = binary.BigEndian.Uint32(random[10:14])
	w.tcc = binary.BigEndian.Uint16(random[14:16])
	w.counter = binary.BigEndian.Uint64(random[16:24])
	w.stateLeft = 30 + freeRand(171)
	w.gapLeft = 50 + freeRand(101)
	w.gapSize = 1 + freeRand(3)
	return w, nil
}

func (w *freeWrap3) Overhead() int { return 56 }

func (w *freeWrap3) WrapInto(dst, payload []byte) (int, error) {
	const headerLen = 40
	wireLen := len(payload) + w.Overhead()
	if len(dst) < wireLen {
		return 0, errors.New("free wrap3: dst too small")
	}
	w.mu.Lock()
	w.stateLeft--
	marker := false
	if w.stateLeft == 0 {
		w.speech = !w.speech
		if w.speech {
			w.stateLeft = 30 + freeRand(171)
			marker = true
		} else {
			w.stateLeft = 5 + freeRand(26)
		}
	}
	seq := w.seq
	w.seq++
	w.gapLeft--
	if w.gapLeft == 0 {
		w.seq += uint16(w.gapSize)
		w.gapLeft = 50 + freeRand(101)
		w.gapSize = 1 + freeRand(3)
	}
	ts := w.timestamp
	w.timestamp += freeTimestampStep()
	tcc := w.tcc
	w.tcc++
	ctr := w.counter
	w.counter++
	level := byte(100 + freeRand(28))
	if w.speech {
		level = 0x80 | byte(20+freeRand(31))
	}
	w.mu.Unlock()

	dst[0] = 0x90
	dst[1] = freeRtpPayload
	if marker { dst[1] |= 0x80 }
	binary.BigEndian.PutUint16(dst[2:4], seq)
	binary.BigEndian.PutUint32(dst[4:8], ts)
	copy(dst[8:12], w.ssrc[:])
	dst[12], dst[13] = 0xbe, 0xde
	binary.BigEndian.PutUint16(dst[14:16], 3)
	dst[16], dst[17] = 0x10, level
	dst[18] = 0x21
	binary.BigEndian.PutUint16(dst[19:21], tcc)
	dst[21] = 0x32
	abs := freeAbsSendTime(w.start)
	dst[22], dst[23], dst[24] = byte(abs>>16), byte(abs>>8), byte(abs)
	dst[25], dst[26], dst[27] = 0, 0, 0
	copy(dst[28:32], w.sessionID[:])
	binary.BigEndian.PutUint64(dst[32:40], ctr)
	copy(dst[headerLen:], payload)
	w.aead.Seal(dst[headerLen:headerLen], dst[28:40], dst[headerLen:headerLen+len(payload)], dst[:headerLen])
	return wireLen, nil
}

func (w *freeWrap3) UnwrapPacket(wire, dst []byte) (int, error) {
	if len(wire) < w.Overhead() {
		return 0, errors.New("free wrap3: packet too short")
	}
	plain, err := w.aead.Open(nil, wire[28:40], wire[40:], wire[:40])
	if err != nil {
		return 0, err
	}
	if len(plain) > len(dst) {
		return 0, errors.New("free wrap3: dst too small")
	}
	copy(dst, plain)
	return len(plain), nil
}

func freeRand(limit int) int {
	if limit <= 1 { return 0 }
	var value [1]byte
	if _, err := rand.Read(value[:]); err != nil { panic(err) }
	return int(value[0]) % limit
}

func freeTimestampStep() uint32 {
	switch r := freeRand(256); {
	case r < 10:
		return 480
	case r < 230:
		return 960
	default:
		return 1920
	}
}

func freeAbsSendTime(start time.Time) uint32 {
	ms := time.Since(start).Milliseconds()
	return uint32((ms/1000)%64)<<18 | uint32((ms%1000)<<18/1000)
}
