package main

import (
	"os"
	"syscall"
)

type Pf struct {
	file *os.File
}

func Open() (*Pf, error) {
	var pf Pf
	var err error
	pf.file, err = os.OpenFile("/dev/pf", os.O_RDWR, 0644)
	return &pf, err
}

func (pf Pf) ioctl(cmd, ptr uintptr) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, pf.file.Fd(), cmd, ptr)
	if e != 0 {
		return e
	}
	return nil
}