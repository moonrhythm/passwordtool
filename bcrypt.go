package passwordtool

import (
	"golang.org/x/crypto/bcrypt"
)

// TODO: cost setup function, run when user call
var bcryptDefaultCost = bcrypt.DefaultCost

// Bcrypt strategy
type Bcrypt struct {
	Cost int
}

func (Bcrypt) String() string {
	return "bcrypt"
}

func (hc Bcrypt) cost() int {
	if hc.Cost <= 0 {
		return bcryptDefaultCost
	}
	return hc.Cost
}

func (hc Bcrypt) hash(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), hc.cost())
	return string(hashed), err
}

func (hc Bcrypt) compare(hashedPassword string, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err == nil {
		return nil
	}
	if err == bcrypt.ErrMismatchedHashAndPassword {
		return ErrMismatched
	}
	if err == bcrypt.ErrHashTooShort {
		return ErrInvalidHash
	}
	return err
}

// Hash hashes password
func (hc Bcrypt) Hash(password string) (string, error) {
	hashed, err := hc.hash(password)
	if err != nil {
		return "", err
	}
	return hc.String() + "$" + string(hashed), nil
}

// Compare compares hashed with password
func (hc Bcrypt) Compare(hashedPassword string, password string) error {
	s, hashed := extract(hashedPassword)
	if s != hc.String() {
		return ErrInvalidHash
	}
	return hc.compare(hashed, password)
}
