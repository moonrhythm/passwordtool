package passwordtool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHasher(t *testing.T) {
	t.Parallel()

	assert.Nil(t, findHasher(""))
	assert.Nil(t, findHasher("invalid"))

	cases := []string{
		"sha256",
		"sha512",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			h := findHasher(c)
			if assert.NotNil(t, h) {
				assert.NotNil(t, h.New())
			}
		})
	}
}
