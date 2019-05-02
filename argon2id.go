package passwordtool

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id strategy
type Argon2id struct {
	S       int
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

func (Argon2id) String() string {
	return "argon2id"
}

func (hc Argon2id) time() uint32 {
	if hc.Time <= 0 {
		return 1
	}
	return hc.Time
}

func (hc Argon2id) memory() uint32 {
	if hc.Memory <= 0 {
		return 64 * 1024
	}
	return hc.Memory
}

func (hc Argon2id) threads() uint8 {
	if hc.Threads <= 0 {
		return 4
	}
	return hc.Threads
}

func (hc Argon2id) keyLen() uint32 {
	if hc.KeyLen <= 0 {
		return 32
	}
	return hc.KeyLen
}

func (hc Argon2id) s() int {
	if hc.S <= 0 {
		return 16
	}
	return hc.S
}

func (hc Argon2id) hash(password string) (string, error) {
	salt, err := generateSalt(hc.s())
	if err != nil {
		return "", err
	}

	time, memory, keyLen := hc.time(), hc.memory(), hc.keyLen()
	dk := argon2.IDKey([]byte(password), salt, time, memory, hc.threads(), keyLen)
	return fmt.Sprintf(
		"%d$%d$%d$%s$%s",
		time, memory, keyLen,
		encodeBase64(salt), encodeBase64(dk),
	), nil
}

func (hc Argon2id) compare(hashed, password string) (bool, error) {
	time, memory, keyLen, salt, dk := hc.decode(hashed)
	if len(dk) == 0 {
		return false, ErrInvalidHashed
	}

	pk := argon2.IDKey([]byte(password), salt, time, memory, hc.threads(), keyLen)
	return subtle.ConstantTimeCompare(dk, pk) == 1, nil
}

func (hc Argon2id) decode(hashed string) (time, memory uint32, keyLen uint32, salt, dk []byte) {
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

// Hash hashes password
func (hc Argon2id) Hash(password string) (string, error) {
	hashed, err := hc.hash(password)
	if err != nil {
		return "", err
	}
	return hc.String() + "$" + string(hashed), nil
}

// Compare compares hashed with password
func (hc Argon2id) Compare(hashedPassword string, password string) (bool, error) {
	s, hashed := extract(hashedPassword)
	if s != hc.String() {
		return false, ErrInvalidComparer
	}
	return hc.compare(hashed, password)
}
