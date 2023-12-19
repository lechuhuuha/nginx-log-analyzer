package ioutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOpenFile(t *testing.T) {
	file, isGzip := OpenFile("../testdata/access.log")
	assert.NotNil(t, file)
	assert.False(t, isGzip)

	file, isGzip = OpenFile("../testdata/access.json.log")
	assert.NotNil(t, file)
	assert.False(t, isGzip)

	file, isGzip = OpenFile("../testdata/access.json.log.1.gz")
	assert.NotNil(t, file)
	assert.True(t, isGzip)
}

func TestReadFile(t *testing.T) {
	file, isGzip := OpenFile("../testdata/access.log")
	reader, err := ReadFile(file, isGzip)
	if err != nil {
		assert.Error(t, err)
	}
	assert.NotNil(t, reader)

	file, isGzip = OpenFile("../testdata/access.json.log")
	reader, err = ReadFile(file, isGzip)
	if err != nil {
		assert.Error(t, err)
	}
	assert.NotNil(t, reader)

	file, isGzip = OpenFile("../testdata/access.json.log.1.gz")
	reader, err = ReadFile(file, isGzip)
	if err != nil {
		assert.Error(t, err)
	}
	assert.NotNil(t, reader)
}
