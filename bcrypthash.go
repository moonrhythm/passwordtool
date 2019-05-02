package passwordtool

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
	return "bcrypt-" + hc.h().String()
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
	return hc.String() + "$" + string(hashed), nil
}

// Compare compares hashed with password
func (hc BcryptHash) Compare(hashedPassword string, password string) bool {
	s, hashed := extract(hashedPassword)
	if s != hc.String() {
		return false
	}

	h := hc.h().New()
	h.Write([]byte(password))
	p := h.Sum(nil)
	return hc.compare(hashed, string(p[:]))
}
