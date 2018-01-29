package httpdigest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMD5Hex(t *testing.T) {
	assert.Equal(t, "827ccb0eea8a706c4c34a16891f84e7b", md5hex("12345"))
}
