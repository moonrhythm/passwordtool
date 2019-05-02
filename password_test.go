package passwordtool_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/moonrhythm/passwordtool"
)

var strategyToTest = []HashComparer{
	Bcrypt{},
	Bcrypt{Cost: 9},
	BcryptHash{},
	BcryptHash{H: SHA256},
	BcryptHash{H: SHA512},
	Scrypt{},
	PBKDF2{},
	PBKDF2{H: SHA256},
	PBKDF2{H: SHA512},
	Argon2id{},
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

			err = s.Compare(hashed, "")
			assert.Equal(t, ErrMismatched, err)

			err = s.Compare(hashed, "invalid")
			assert.Equal(t, ErrMismatched, err)

			err = s.Compare(hashed, "superman")
			assert.NoError(t, err)

			err = s.Compare("", "invalid")
			assert.Equal(t, ErrInvalidHash, err)

			err = s.Compare("invalid", "invalid")
			assert.Equal(t, ErrInvalidHash, err)

			err = s.Compare("invalid$password", "invalid")
			assert.Equal(t, ErrInvalidHash, err)

			err = s.Compare(s.String()+"$password", "invalid")
			assert.Equal(t, ErrInvalidHash, err)

			err = s.Compare(s.String()+"$a$b$c", "invalid")
			assert.Equal(t, ErrInvalidHash, err)

			err = s.Compare(s.String()+"$a$b$c$d", "invalid")
			assert.Equal(t, ErrInvalidHash, err)

			err = s.Compare(s.String()+"$a$b$c$d$e", "invalid")
			assert.Equal(t, ErrInvalidHash, err)

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
