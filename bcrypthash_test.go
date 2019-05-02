package passwordtool_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	. "github.com/moonrhythm/passwordtool"
)

func TestBcryptHash(t *testing.T) {
	t.Parallel()

	hashed, err := BcryptHash{}.Hash("superman")
	assert.NoError(t, err)
	assert.NotEmpty(t, hashed)

	err = BcryptHash{}.Compare(hashed, "superman")
	assert.NoError(t, err)

	hashed, err = BcryptHash{H: SHA512}.Hash("superman")
	assert.NoError(t, err)
	assert.NotEmpty(t, hashed)

	err = BcryptHash{H: SHA512}.Compare(hashed, "superman")
	assert.NoError(t, err)

	err = BcryptHash{H: SHA256}.Compare(hashed, "superman")
	assert.NoError(t, err)

	err = BcryptHash{}.Compare(hashed, "superman")
	assert.NoError(t, err)
}
