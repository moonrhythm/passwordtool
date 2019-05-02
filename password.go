package passwordtool

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

var strategies = []HashComparer{
	Bcrypt{},
	BcryptHash{},
	Scrypt{},
	PBKDF2{},
	Argon2{},
}

// HashComparer interface
type HashComparer interface {
	fmt.Stringer

	Hash(password string) (string, error)
	Compare(hashedPassword string, password string) bool
}

var defaultStrategy = Argon2{}

// Hash hashes password using default strategy
func Hash(password string) (string, error) {
	return defaultStrategy.Hash(password)
}

// Compare compares hashed and password
func Compare(hashedPassword string, password string) bool {
	hc := findHC(hashedPassword)
	if hc == nil {
		return false
	}
	return hc.Compare(hashedPassword, password)
}

func findHC(hashedPassword string) HashComparer {
	if len(hashedPassword) == 0 {
		return nil
	}

	for _, s := range strategies {
		if strings.HasPrefix(hashedPassword, s.String()+"$") {
			return s
		}
	}
	return nil
}

func extract(hashedPassword string) (strategy string, hashed string) {
	if len(hashedPassword) == 0 {
		return
	}

	ps := strings.SplitN(hashedPassword, "$", 2)
	if len(ps) != 2 {
		return
	}

	return ps[0], ps[1]
}

func generateSalt(s int) ([]byte, error) {
	p := make([]byte, s)
	_, err := rand.Read(p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func encodeBase64(p []byte) string {
	return base64.RawStdEncoding.EncodeToString(p)
}

func decodeBase64(s string) []byte {
	p, _ := base64.RawStdEncoding.DecodeString(s)
	return p
}