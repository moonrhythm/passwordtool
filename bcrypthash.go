package passwordtool

import (
	"strings"
)

// BcryptHash strategy
type BcryptHash struct {
	Bcrypt

	H Hasher
}

func (hc BcryptHash) h() Hasher {
	if hc.H == nil {
		return SHA256
	}
	return hc.H
}

func (hc BcryptHash) String() string {
	return "bcrypt-hash"
}

func (hc BcryptHash) decode(hashed string) (h Hasher, k string) {
	xs := strings.SplitN(hashed, "$", 2)
	if len(xs) != 2 {
		return
	}

	h = findHasher(xs[0])
	if h == nil {
		return
	}

	k = xs[1]
	return
}

// Hash hashes password
func (hc BcryptHash) Hash(password string) (string, error) {
	h := hc.h().New()
	h.Write([]byte(password))
	p := h.Sum(nil)
	hashed, err := hc.hash(string(p[:]))
	if err != nil {
		return "", err
	}
	return hc.String() + "$" + hc.h().String() + "$" + string(hashed), nil
}

// Compare compares hashed with password
func (hc BcryptHash) Compare(hashedPassword string, password string) error {
	s, hashed := extract(hashedPassword)
	if s != hc.String() {
		return ErrInvalidHash
	}

	hasher, k := hc.decode(hashed)
	if hasher == nil || k == "" {
		return ErrInvalidHash
	}

	h := hasher.New()
	h.Write([]byte(password))
	p := h.Sum(nil)
	return hc.compare(k, string(p[:]))
}
