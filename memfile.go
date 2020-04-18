package main

import (
	"os"
)

func createFileMapping(content []byte, name string) (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	go func() {
		defer w.Close()
		w.Write(content)
	}()
	return r, nil
}
