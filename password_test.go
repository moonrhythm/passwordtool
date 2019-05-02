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

			assert.False(t, s.Compare(hashed, ""))
			assert.False(t, s.Compare(hashed, "invalid"))
			assert.True(t, s.Compare(hashed, "superman"))

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

	assert.False(t, Compare(hashed, ""))
	assert.False(t, Compare(hashed, "invalid"))
	assert.True(t, Compare(hashed, "superman"))
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

			assert.False(t, Compare(hashed, ""))
			assert.False(t, Compare(hashed, "invalid"))
			assert.True(t, Compare(hashed, "superman"))
		})
	}
}
