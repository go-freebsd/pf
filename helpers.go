package main

import (
	"fmt"
	"unsafe"
)

// #include "string.h"
import "C"

func CStringCopy(dst unsafe.Pointer, src string, size int) error {
	if C.strlcpy((*C.char)(dst), C.CString(src), C.size_t(size)) >= C.size_t(size) {
		return fmt.Errorf("CSafeStringCopy: string '%s' to long (max: %d was: %d)",
			src, size, len(src))
	}
	return nil
}
