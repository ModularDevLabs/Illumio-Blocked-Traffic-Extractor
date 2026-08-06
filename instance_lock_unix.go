//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type instanceLock struct {
	file *os.File
}

func acquireInstanceLock() (*instanceLock, error) {
	storePath, err := automationStorePath()
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(storePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(dir, "instance.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("another Illumio Traffic Tool process is already running")
	}
	return &instanceLock{file: file}, nil
}

func (lock *instanceLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	_ = unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	return lock.file.Close()
}
