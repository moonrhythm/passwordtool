package passwordtool

import (
	"golang.org/x/crypto/bcrypt"
)

// Bcrypt strategy
type Bcrypt struct {
	Cost int
}

func (Bcrypt) String() string {
	return "bcrypt"
}

func (hc Bcrypt) cost() int {
	if hc.Cost <= 0 {
		return 10
	}
	return hc.Cost
}

func (hc Bcrypt) hash(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), hc.cost())
	return string(hashed), err
}

func (hc Bcrypt) compare(hashedPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
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
func (hc Bcrypt) Compare(hashedPassword string, password string) bool {
	s, hashed := extract(hashedPassword)
	if s != hc.String() {
		return false
	}
	return hc.compare(hashed, password)
}
