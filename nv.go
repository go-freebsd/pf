package pf

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// #cgo LDFLAGS: -lnv
// #include <stdlib.h>
// #include <string.h>
// #include <sys/types.h>
// #include <sys/nv.h>
// #include <sys/ioctl.h>
// #include <net/if.h>
// #include <net/pfvar.h>
import "C"

// nv wraps a libnv name/value list as used by the NV flavoured pf
// ioctls (DIOCGETRULENV, DIOCGETSTATUSNV). FreeBSD 15 removed the struct
// based variants of these ioctls, FreeBSD 14 offers both.
type nv struct {
	p *C.nvlist_t
}

func newNV() *nv {
	return &nv{p: C.nvlist_create(0)}
}

// destroy frees the list and everything it owns
func (n *nv) destroy() {
	if n != nil && n.p != nil {
		C.nvlist_destroy(n.p)
		n.p = nil
	}
}

func (n *nv) addNumber(name string, v uint64) {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	C.nvlist_add_number(n.p, c, C.uint64_t(v))
}

func (n *nv) addBool(name string, v bool) {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	C.nvlist_add_bool(n.p, c, C.bool(v))
}

func (n *nv) addString(name, v string) {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	cv := C.CString(v)
	defer C.free(unsafe.Pointer(cv))
	C.nvlist_add_string(n.p, c, cv)
}

func (n *nv) number(name string) (uint64, bool) {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	if !C.nvlist_exists_number(n.p, c) {
		return 0, false
	}
	return uint64(C.nvlist_get_number(n.p, c)), true
}

func (n *nv) boolean(name string) (bool, bool) {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	if !C.nvlist_exists_bool(n.p, c) {
		return false, false
	}
	return bool(C.nvlist_get_bool(n.p, c)), true
}

func (n *nv) str(name string) (string, bool) {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	if !C.nvlist_exists_string(n.p, c) {
		return "", false
	}
	return C.GoString(C.nvlist_get_string(n.p, c)), true
}

func (n *nv) binary(name string) ([]byte, bool) {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	if !C.nvlist_exists_binary(n.p, c) {
		return nil, false
	}
	var size C.size_t
	p := C.nvlist_get_binary(n.p, c, &size)
	return C.GoBytes(p, C.int(size)), true
}

func (n *nv) numbers(name string) ([]uint64, bool) {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	if !C.nvlist_exists_number_array(n.p, c) {
		return nil, false
	}
	var cnt C.size_t
	p := C.nvlist_get_number_array(n.p, c, &cnt)
	out := make([]uint64, int(cnt))
	copy(out, unsafe.Slice((*uint64)(unsafe.Pointer(p)), int(cnt)))
	return out, true
}

// child returns a nested list; it is owned by n and must not be destroyed
func (n *nv) child(name string) (*nv, bool) {
	c := C.CString(name)
	defer C.free(unsafe.Pointer(c))
	if !C.nvlist_exists_nvlist(n.p, c) {
		return nil, false
	}
	return &nv{p: (*C.nvlist_t)(unsafe.Pointer(C.nvlist_get_nvlist(n.p, c)))}, true
}

// pack serializes the list
func (n *nv) pack() ([]byte, error) {
	var size C.size_t
	p := C.nvlist_pack(n.p, &size)
	if p == nil {
		return nil, errors.New("nvlist_pack failed")
	}
	defer C.free(p)
	return C.GoBytes(p, C.int(size)), nil
}

// unpackNV parses a serialized list
func unpackNV(b []byte) (*nv, error) {
	if len(b) == 0 {
		return nil, errors.New("empty nvlist")
	}
	p := C.nvlist_unpack(unsafe.Pointer(&b[0]), C.size_t(len(b)), 0)
	if p == nil {
		return nil, errors.New("nvlist_unpack failed")
	}
	return &nv{p: p}, nil
}

// nvIoctl sends req (may be nil) with an NV ioctl and returns the reply.
// The reply buffer grows until the kernel stops answering ENOSPC.
func (dev *ioctlDev) nvIoctl(cmd uintptr, req *nv) (*nv, error) {
	var in []byte
	if req != nil {
		var err error
		in, err = req.pack()
		if err != nil {
			return nil, err
		}
	}
	size := 64 << 10
	for tries := 0; tries < 8; tries++ {
		if size < len(in) {
			size = len(in)
		}
		buf := C.malloc(C.size_t(size))
		if buf == nil {
			return nil, errors.New("out of memory")
		}
		C.memset(buf, 0, C.size_t(size))
		if len(in) > 0 {
			C.memcpy(buf, unsafe.Pointer(&in[0]), C.size_t(len(in)))
		}
		var pnv C.struct_pfioc_nv
		pnv.data = buf
		pnv.len = C.size_t(len(in))
		pnv.size = C.size_t(size)
		err := dev.ioctl(cmd, unsafe.Pointer(&pnv))
		if err == nil {
			out := C.GoBytes(buf, C.int(pnv.len))
			C.free(buf)
			return unpackNV(out)
		}
		need := int(pnv.len)
		C.free(buf)
		if !errors.Is(err, syscall.ENOSPC) {
			return nil, err
		}
		if need > size {
			size = need
		} else {
			size *= 2
		}
	}
	return nil, fmt.Errorf("nv ioctl: reply does not fit")
}

// dump lists the names and types of the list, children indented; it is for
// looking at what the kernel sends.
func (n *nv) dump(indent string) []string {
	var out []string
	var cookie unsafe.Pointer
	for {
		var typ C.int
		name := C.nvlist_next(n.p, &typ, &cookie)
		if name == nil {
			break
		}
		gn := C.GoString(name)
		out = append(out, fmt.Sprintf("%s%s (type %d)", indent, gn, int(typ)))
		if int(typ) == C.NV_TYPE_NVLIST {
			if child, ok := n.child(gn); ok {
				out = append(out, child.dump(indent+"  ")...)
			}
		}
	}
	return out
}
