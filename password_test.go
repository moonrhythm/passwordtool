package passwordtool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStrategies(t *testing.T) {
	t.Parallel()

	for _, s := range strategies {
		s := s
		t.Run(s.String(), func(t *testing.T) {
			t.Parallel()

			hashed, err := s.Hash("superman")
			assert.NoError(t, err)
			assert.NotEmpty(t, hashed)
			t.Logf("hashed: %s", hashed)

			equal, err := s.Compare(hashed, "")
			assert.NoError(t, err)
			assert.False(t, equal)

			equal, err = s.Compare(hashed, "invalid")
			assert.NoError(t, err)
			assert.False(t, equal)

			equal, err = s.Compare(hashed, "superman")
			assert.NoError(t, err)
			assert.True(t, equal)

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

	equal, err := Compare(hashed, "")
	assert.NoError(t, err)
	assert.False(t, equal)

	equal, err = Compare(hashed, "invalid")
	assert.NoError(t, err)
	assert.False(t, equal)

	equal, err = Compare(hashed, "superman")
	assert.NoError(t, err)
	assert.True(t, equal)
}

func TestCompare(t *testing.T) {
	t.Parallel()

	for _, s := range strategies {
		s := s
		t.Run(s.String(), func(t *testing.T) {
			t.Parallel()

			hashed, err := s.Hash("superman")
			assert.NoError(t, err)
			assert.NotEmpty(t, hashed)

			equal, err := Compare(hashed, "")
			assert.NoError(t, err)
			assert.False(t, equal)

			equal, err = Compare(hashed, "invalid")
			assert.NoError(t, err)
			assert.False(t, equal)

			equal, err = Compare(hashed, "superman")
			assert.NoError(t, err)
			assert.True(t, equal)
		})
	}
}
