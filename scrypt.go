package passwordtool

import (
	"crypto/subtle"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
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
		return 32768
	}
	return hc.N
}

func (hc Scrypt) r() int {
	if hc.R <= 0 {
		return 8
	}
	return hc.R
}

func (hc Scrypt) p() int {
	if hc.P <= 0 {
		return 1
	}
	return hc.P
}

func (hc Scrypt) s() int {
	if hc.S <= 0 {
		return 16
	}
	return hc.S
}

func (hc Scrypt) k() int {
	if hc.K <= 0 {
		return 32
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

func (hc Scrypt) compare(hashed, password string) (bool, error) {
	n, r, p, salt, dk := hc.decode(hashed)
	if len(dk) == 0 {
		return false, ErrInvalidHashed
	}

	pk, err := scrypt.Key([]byte(password), salt, n, r, p, len(dk))
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(dk, pk) == 1, nil
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
func (hc Scrypt) Compare(hashedPassword string, password string) (bool, error) {
	s, hashed := extract(hashedPassword)
	if s != hc.String() {
		return false, ErrInvalidComparer
	}
	return hc.compare(hashed, password)
}
