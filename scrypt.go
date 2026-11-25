package passwordtool

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

const (
	scryptDefaultN = 32768
	scryptDefaultR = 8
	scryptDefaultP = 1
	scryptDefaultS = 16
	scryptDefaultK = 32
)

// Scrypt strategy
type Scrypt struct {
	N int
	R int
	P int
	S int
	K int
}

func (Scrypt) String() string {
	return "scrypt"
}

func (hc Scrypt) n() int {
	if hc.N <= 0 {
		return scryptDefaultN
	}
	return hc.N
}

func (hc Scrypt) r() int {
	if hc.R <= 0 {
		return scryptDefaultR
	}
	return hc.R
}

func (hc Scrypt) p() int {
	if hc.P <= 0 {
		return scryptDefaultP
	}
	return hc.P
}

func (hc Scrypt) s() int {
	if hc.S <= 0 {
		return scryptDefaultS
	}
	return hc.S
}

func (hc Scrypt) k() int {
	if hc.K <= 0 {
		return scryptDefaultK
	}
	return hc.K
}

func (hc Scrypt) hash(password string) (string, error) {
	n, r, p, keyLen := hc.n(), hc.r(), hc.p(), hc.k()
	if err := checkScryptParams(n, r, p); err != nil {
		return "", err
	}
	if err := checkKeyLen(keyLen); err != nil {
		return "", err
	}
	if err := checkSaltLen(hc.s()); err != nil {
		return "", err
	}

	salt, err := generateSalt(hc.s())
	if err != nil {
		return "", err
	}

	dk, err := scrypt.Key([]byte(password), salt, n, r, p, keyLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf(
		"%d$%d$%d$%s$%s",
		n, r, p,
		encodeBase64(salt), encodeBase64(dk),
	), nil
}

func (hc Scrypt) compare(hashed, password string) error {
	n, r, p, salt, dk, err := hc.decode(hashed)
	if err != nil {
		return err
	}

	pk, err := scrypt.Key([]byte(password), salt, n, r, p, len(dk))
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(dk, pk) == 1 {
		return nil
	}
	return ErrMismatched
}

func (hc Scrypt) decode(hashed string) (n, r, p int, salt, dk []byte, err error) {
	xs := strings.Split(hashed, "$")
	if len(xs) != 5 {
		err = ErrInvalidHash
		return
	}

	n, err = strconv.Atoi(xs[0])
	if err != nil {
		err = ErrInvalidHash
		return
	}
	r, err = strconv.Atoi(xs[1])
	if err != nil {
		err = ErrInvalidHash
		return
	}
	p, err = strconv.Atoi(xs[2])
	if err != nil {
		err = ErrInvalidHash
		return
	}
	if err = checkScryptParams(n, r, p); err != nil {
		return
	}
	salt, err = decodeBase64(xs[3], minSaltLen, maxSaltLen)
	if err != nil {
		return
	}
	dk, err = decodeBase64(xs[4], 1, maxKeyLen)
	return
}

// Hash hashes password
func (hc Scrypt) Hash(password string) (string, error) {
	hashed, err := hc.hash(password)
	if err != nil {
		return "", err
	}
	return hc.String() + "$" + string(hashed), nil
}

// Compare compares hashed with password
func (hc Scrypt) Compare(hashedPassword string, password string) error {
	s, hashed := extract(hashedPassword)
	if s != hc.String() {
		return ErrInvalidHash
	}
	return hc.compare(hashed, password)
}
