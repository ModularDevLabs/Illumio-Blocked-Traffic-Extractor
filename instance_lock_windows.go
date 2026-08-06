//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type instanceLock struct {
	file       *os.File
	overlapped windows.Overlapped
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
	lock := &instanceLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &lock.overlapped); err != nil {
		file.Close()
		return nil, fmt.Errorf("another Illumio Traffic Tool process is already running")
	}
	return lock, nil
}

func (lock *instanceLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	_ = windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, 1, 0, &lock.overlapped)
	return lock.file.Close()
}
