package passwordtool

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2 strategy
type Argon2 struct {
	S       int
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

func (Argon2) String() string {
	return "argon2"
}

func (hc Argon2) time() uint32 {
	if hc.Time <= 0 {
		return 3
	}
	return hc.Time
}

func (hc Argon2) memory() uint32 {
	if hc.Memory <= 0 {
		return 32 * 1024
	}
	return hc.Memory
}

func (hc Argon2) threads() uint8 {
	if hc.Threads <= 0 {
		return 4
	}
	return hc.Threads
}

func (hc Argon2) keyLen() uint32 {
	if hc.KeyLen <= 0 {
		return 32
	}
	return hc.KeyLen
}

func (hc Argon2) s() int {
	if hc.S <= 0 {
		return 16
	}
	return hc.S
}

func (hc Argon2) hash(password string) (string, error) {
	salt, err := generateSalt(hc.s())
	if err != nil {
		return "", err
	}

	time, memory, keyLen := hc.time(), hc.memory(), hc.keyLen()
	dk := argon2.Key([]byte(password), salt, time, memory, hc.threads(), keyLen)
	return fmt.Sprintf(
		"%d$%d$%d$%s$%s",
		time, memory, keyLen,
		encodeBase64(salt), encodeBase64(dk),
	), nil
}

func (hc Argon2) compare(hashed, password string) bool {
	time, memory, keyLen, salt, dk := hc.decode(hashed)
	if len(dk) == 0 {
		return false
	}

	pk := argon2.Key([]byte(password), salt, time, memory, hc.threads(), keyLen)
	return subtle.ConstantTimeCompare(dk, pk) == 1
}

func (hc Argon2) decode(hashed string) (time, memory uint32, keyLen uint32, salt, dk []byte) {
	xs := strings.Split(hashed, "$")
	if len(xs) != 5 {
		return
	}

	rawTime, err := strconv.ParseUint(xs[0], 10, 32)
	if err != nil {
		return
	}
	time = uint32(rawTime)

	rawMemory, err := strconv.ParseUint(xs[1], 10, 32)
	if err != nil {
		return
	}
	memory = uint32(rawMemory)

	rawKeyLen, err := strconv.ParseUint(xs[2], 10, 32)
	if err != nil {
		return
	}
	keyLen = uint32(rawKeyLen)

	salt = decodeBase64(xs[3])
	dk = decodeBase64(xs[4])
	return
}

func (hc Argon2) Hash(password string) (string, error) {
	hashed, err := hc.hash(password)
	if err != nil {
		return "", err
	}
	return hc.String() + "$" + string(hashed), nil
}

func (hc Argon2) Compare(hashedPassword string, password string) bool {
	s, hashed := extract(hashedPassword)
	if s != hc.String() {
		return false
	}
	return hc.compare(hashed, password)
}
