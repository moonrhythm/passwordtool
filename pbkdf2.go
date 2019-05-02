package passwordtool

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// PBKDF2 strategy
type PBKDF2 struct {
	Iter   int
	KeyLen int
	S      int
	H      Hasher
}

func (PBKDF2) String() string {
	return "pbkdf2"
}

func (hc PBKDF2) iter() int {
	if hc.Iter <= 0 {
		return 10000
	}
	return hc.Iter
}

func (hc PBKDF2) keyLen() int {
	if hc.KeyLen <= 0 {
		return 32
	}
	return hc.KeyLen
}

func (hc PBKDF2) s() int {
	if hc.S <= 0 {
		return 8
	}
	return hc.S
}

func (hc PBKDF2) h() Hasher {
	return SHA512
}

func (hc PBKDF2) hash(password string) (string, error) {
	salt, err := generateSalt(hc.s())
	if err != nil {
		return "", err
	}

	h, iter, keyLen := hc.h(), hc.iter(), hc.keyLen()
	dk := pbkdf2.Key([]byte(password), salt, iter, keyLen, h.New)
	return fmt.Sprintf(
		"%s$%d$%d$%s$%s",
		h, iter, keyLen,
		encodeBase64(salt), encodeBase64(dk),
	), nil
}

func (hc PBKDF2) compare(hashed, password string) error {
	h, iter, keyLen, salt, dk := hc.decode(hashed)
	if h == nil {
		return ErrInvalidHash
	}
	if len(dk) == 0 {
		return ErrInvalidHash
	}

	pk := pbkdf2.Key([]byte(password), salt, iter, keyLen, h.New)
	if subtle.ConstantTimeCompare(dk, pk) == 1 {
		return nil
	}
	return ErrMismatched
}

func (hc PBKDF2) decode(hashed string) (h Hasher, iter, keyLen int, salt, dk []byte) {
	xs := strings.Split(hashed, "$")
	if len(xs) != 5 {
		return
	}

	h = findHasher(xs[0])
	if h == nil {
		return
	}

	var err error
	iter, err = strconv.Atoi(xs[1])
	if err != nil {
		return
	}
	keyLen, err = strconv.Atoi(xs[2])
	if err != nil {
		return
	}
	salt = decodeBase64(xs[3])
	dk = decodeBase64(xs[4])
	return
}

// Hash hashes password
func (hc PBKDF2) Hash(password string) (string, error) {
	hashed, err := hc.hash(password)
	if err != nil {
		return "", err
	}
	return hc.String() + "$" + string(hashed), nil
}

// Compare compares hashed with password
func (hc PBKDF2) Compare(hashedPassword string, password string) error {
	s, hashed := extract(hashedPassword)
	if s != hc.String() {
		return ErrInvalidHash
	}
	return hc.compare(hashed, password)
}
