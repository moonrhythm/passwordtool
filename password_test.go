package passwordtool_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/moonrhythm/passwordtool"
)

var strategyToTest = []HashComparer{
	Argon2id{},
	Argon2id{S: 32, Time: 1, Memory: 32 * 1024, Threads: 2, KeyLen: 32},
	PBKDF2{H: SHA512},
	PBKDF2{H: SHA256},
	PBKDF2{H: SHA1},
	PBKDF2{Iter: 4096, KeyLen: 16, H: SHA512, S: 32},
	PBKDF2{},
	Scrypt{},
	Scrypt{N: 16384, R: 8, P: 1, S: 8, K: 16},
	BcryptHash{H: SHA512},
	BcryptHash{H: SHA256},
	BcryptHash{H: SHA1},
	BcryptHash{},
	Bcrypt{Cost: 9},
	Bcrypt{},
}

func TestStrategies(t *testing.T) {
	t.Parallel()

	for _, s := range strategyToTest {
		s := s
		t.Run(s.String(), func(t *testing.T) {
			t.Parallel()

			hashed, err := s.Hash("superman")
			assert.NoError(t, err)
			assert.NotEmpty(t, hashed)
			t.Logf("hashed: %s", hashed)

			assert.Equal(t, ErrMismatched, s.Compare(hashed, ""))
			assert.Equal(t, ErrMismatched, s.Compare(hashed, "invalid"))
			assert.NoError(t, s.Compare(hashed, "superman"))
			assert.Equal(t, ErrInvalidHash, s.Compare("", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare("invalid", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare("invalid$password", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare(s.String()+"$password", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare(s.String()+"$a$b$c", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare(s.String()+"$a$b$c$d", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare(s.String()+"$sha256$a$b$c$d", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare(s.String()+"$sha256$1$b$c$d", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare(s.String()+"$a$b$c$d$e", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare(s.String()+"$1$b$c$d$e", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare(s.String()+"$1$2$c$d$e", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare(s.String()+"$a$b$c$d$e$f", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare(s.String()+"$1$b$c$d$e$f", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare(s.String()+"$1$2$c$d$e$f", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare(s.String()+"$1$2$3$d$e$f", "invalid"))
			assert.Equal(t, ErrInvalidHash, s.Compare(s.String()+"$1$2$3$4$e$f", "invalid"))

			hashed2, err := s.Hash("superman")
			assert.NoError(t, err)
			assert.NotEmpty(t, hashed2)
			assert.NotEqual(t, hashed, hashed2)
		})
	}
}

func TestHashCompare(t *testing.T) {
	t.Parallel()

	hashed, err := Hash("superman")
	assert.NoError(t, err)
	assert.NotEmpty(t, hashed)

	err = Compare(hashed, "")
	assert.Equal(t, ErrMismatched, err)

	err = Compare(hashed, "invalid")
	assert.Equal(t, ErrMismatched, err)

	err = Compare(hashed, "superman")
	assert.NoError(t, err)
}

func TestCompare(t *testing.T) {
	t.Parallel()

	for _, s := range strategyToTest {
		s := s
		t.Run(s.String(), func(t *testing.T) {
			t.Parallel()

			hashed, err := s.Hash("superman")
			assert.NoError(t, err)
			assert.NotEmpty(t, hashed)

			err = Compare(hashed, "")
			assert.Equal(t, ErrMismatched, err)

			err = Compare(hashed, "invalid")
			assert.Equal(t, ErrMismatched, err)

			err = Compare("", "invalid")
			assert.Equal(t, ErrInvalidHash, err)

			err = Compare("$invalid$password", "invalid")
			assert.Equal(t, ErrInvalidHash, err)

			err = Compare("$"+s.String()+"$password", "invalid")
			assert.Equal(t, ErrInvalidHash, err)

			err = Compare(hashed, "superman")
			assert.NoError(t, err)
		})
	}
}
