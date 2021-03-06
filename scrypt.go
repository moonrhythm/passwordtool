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
	salt, err := generateSalt(hc.s())
	if err != nil {
		return "", err
	}

	n, r, p := hc.n(), hc.r(), hc.p()
	dk, err := scrypt.Key([]byte(password), salt, n, r, p, hc.k())
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
	n, r, p, salt, dk := hc.decode(hashed)
	if len(dk) == 0 {
		return ErrInvalidHash
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

func (hc Scrypt) decode(hashed string) (n, r, p int, salt, dk []byte) {
	xs := strings.Split(hashed, "$")
	if len(xs) != 5 {
		return
	}

	var err error
	n, err = strconv.Atoi(xs[0])
	if err != nil {
		return
	}
	r, err = strconv.Atoi(xs[1])
	if err != nil {
		return
	}
	p, err = strconv.Atoi(xs[2])
	if err != nil {
		return
	}
	salt = decodeBase64(xs[3])
	dk = decodeBase64(xs[4])
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
