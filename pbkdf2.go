package passwordtool

import (
	"cmp"
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	pbkdf2DefaultIter   = 220_000
	pbkdf2SHA256Iter    = 600_000
	pbkdf2SHA1Iter      = 1_400_000
	pbkdf2DefaultKeyLen = 32
	pbkdf2DefaultS      = 16
)

var pbkdf2DefaultH = SHA512

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
	if hc.Iter > 0 {
		return hc.Iter
	}
	// Zero Iter follows the OWASP floor for the selected HMAC.
	switch hc.h() {
	case SHA256:
		return pbkdf2SHA256Iter
	case SHA1:
		return pbkdf2SHA1Iter
	default:
		return pbkdf2DefaultIter
	}
}

func (hc PBKDF2) keyLen() int {
	if hc.KeyLen <= 0 {
		return pbkdf2DefaultKeyLen
	}
	return hc.KeyLen
}

func (hc PBKDF2) s() int {
	if hc.S <= 0 {
		return pbkdf2DefaultS
	}
	return hc.S
}

func (hc PBKDF2) h() Hasher {
	return cmp.Or(hc.H, pbkdf2DefaultH)
}

func (hc PBKDF2) hash(password string) (string, error) {
	h, iter, keyLen := hc.h(), hc.iter(), hc.keyLen()
	if err := checkPBKDF2(iter, keyLen); err != nil {
		return "", err
	}
	if err := checkSaltLen(hc.s()); err != nil {
		return "", err
	}
	if err := checkHashSizes(hc.s(), keyLen); err != nil {
		return "", err
	}

	salt, err := generateSalt(hc.s())
	if err != nil {
		return "", err
	}

	dk := pbkdf2.Key([]byte(password), salt, iter, keyLen, h.New)
	return fmt.Sprintf(
		"%s$%d$%d$%s$%s",
		h, iter, keyLen,
		encodeBase64(salt), encodeBase64(dk),
	), nil
}

func (hc PBKDF2) compare(hashed, password string) error {
	h, iter, keyLen, salt, dk, err := hc.decode(hashed)
	if err != nil {
		return err
	}

	pk := pbkdf2.Key([]byte(password), salt, iter, keyLen, h.New)
	if subtle.ConstantTimeCompare(dk, pk) == 1 {
		return nil
	}
	return ErrMismatched
}

func (hc PBKDF2) decode(hashed string) (h Hasher, iter, keyLen int, salt, dk []byte, err error) {
	xs := strings.Split(hashed, "$")
	if len(xs) != 5 {
		err = ErrInvalidHash
		return
	}

	h = findHasher(xs[0])
	if h == nil {
		err = ErrInvalidHash
		return
	}

	iter, err = strconv.Atoi(xs[1])
	if err != nil {
		err = ErrInvalidHash
		return
	}
	keyLen, err = strconv.Atoi(xs[2])
	if err != nil {
		err = ErrInvalidHash
		return
	}
	if err = checkPBKDF2(iter, keyLen); err != nil {
		return
	}
	salt, err = decodeBase64(xs[3], minSaltLen, maxSaltLen)
	if err != nil {
		return
	}
	dk, err = decodeBase64(xs[4], keyLen, keyLen)
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
