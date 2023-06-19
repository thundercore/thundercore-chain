package utils

import (
	// Standard imports
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

const fileURI = "file://"
const httpURI = "http://"

// fetch takes a URL and fetches it. It returns an error if the size of the body in bytes
// exceeds the expected maximum size.  Not intended to be used to fetch extremely large
// files.
func Fetch(url string, maxSize int) ([]byte, error) {
	var buf []byte
	var err error

	if strings.HasPrefix(url, httpURI) {
		res, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		r := io.LimitReader(res.Body, int64(maxSize+1))
		buf, _ = ioutil.ReadAll(r)
	} else {
		fName := url
		if strings.HasPrefix(url, fileURI) {
			fName = strings.TrimPrefix(url, fileURI)
		}
		buf, err = ioutil.ReadFile(fName)
	}
	if err != nil {
		return nil, err
	}

	if len(buf) > maxSize {
		return nil, fmt.Errorf("%s: too much data, got %d bytes", url, len(buf))
	}
	return buf, nil
}
