package passwordtool

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Errors
var (
	ErrInvalidHash = errors.New("passwordtool: invalid hash password")
	ErrMismatched  = errors.New("passwordtool: hashed and password mismatched")
)

var strategies = []HashComparer{
	Argon2id{},
	PBKDF2{},
	Scrypt{},
	BcryptHash{},
	Bcrypt{},
}

// HashComparer interface
type HashComparer interface {
	fmt.Stringer

	Hash(password string) (string, error)
	Compare(hashedPassword string, password string) error
}

var defaultStrategy = Argon2id{}

// Hash hashes password using default strategy
func Hash(password string) (string, error) {
	return defaultStrategy.Hash(password)
}

// Compare compares hashed and password
// returns nil if hashed and password equal
func Compare(hashedPassword string, password string) error {
	hc := findHC(hashedPassword)
	if hc == nil {
		return ErrInvalidHash
	}
	return hc.Compare(hashedPassword, password)
}

func findHC(hashedPassword string) HashComparer {
	if len(hashedPassword) == 0 {
		return nil
	}

	i := slices.IndexFunc(strategies, func(s HashComparer) bool {
		return strings.HasPrefix(hashedPassword, s.String()+"$")
	})
	if i < 0 {
		return nil
	}
	return strategies[i]
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

func decodeBase64(s string, minLen, maxLen int) ([]byte, error) {
	if minLen < 0 || maxLen < minLen || len(s) > base64.RawStdEncoding.EncodedLen(maxLen) {
		return nil, ErrInvalidHash
	}
	p, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil || len(p) < minLen || len(p) > maxLen {
		return nil, ErrInvalidHash
	}
	return p, nil
}
