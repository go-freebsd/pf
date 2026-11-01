package pf

import (
	"reflect"
	"testing"
)

// The libnv wrapper is exercised without a kernel by packing and unpacking.
func TestNVRoundTrip(t *testing.T) {
	n := newNV()
	defer n.destroy()
	n.addNumber("nr", 7)
	n.addBool("clear_counter", true)
	n.addString("anchor", "a/b")

	b, err := n.pack()
	if err != nil {
		t.Fatal(err)
	}
	m, err := unpackNV(b)
	if err != nil {
		t.Fatal(err)
	}
	defer m.destroy()

	if v, ok := m.number("nr"); !ok || v != 7 {
		t.Errorf("nr = %d %v", v, ok)
	}
	if v, ok := m.boolean("clear_counter"); !ok || !v {
		t.Errorf("clear_counter = %v %v", v, ok)
	}
	if v, ok := m.str("anchor"); !ok || v != "a/b" {
		t.Errorf("anchor = %q %v", v, ok)
	}
	if _, ok := m.number("missing"); ok {
		t.Error("missing key reported as present")
	}
	if _, ok := m.numbers("missing"); ok {
		t.Error("missing array reported as present")
	}
	if !reflect.DeepEqual(b, mustPack(t, m)) {
		t.Error("repacking changed the bytes")
	}
}

func mustPack(t *testing.T, n *nv) []byte {
	t.Helper()
	b, err := n.pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
