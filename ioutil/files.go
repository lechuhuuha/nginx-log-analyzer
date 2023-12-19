package ioutil

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func OpenFile(path string) (*os.File, bool) {
	file, err := os.Open(path)
	if err != nil {
		Fatal("open file error: %v\n", err.Error())
		return nil, false
	}

	ext := filepath.Ext(file.Name())
	return file, strings.EqualFold(".gz", ext)
}

func ReadFile(file *os.File, isGzip bool) (*bufio.Reader, error) {
	if isGzip {
		gzipReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("gzip new reader error: %v\n", err.Error())
		}
		return bufio.NewReader(gzipReader), nil
	} else {
		return bufio.NewReader(file), nil
	}
}
