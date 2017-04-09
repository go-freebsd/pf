package pf

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddressMask(t *testing.T) {
	a := newAddress()
	// all addresses are an address mask by default
	assert.True(t, a.Mask())

	tests := []struct{ address, str string }{
		{"10.0.1.1", "10.0.1.1/32"},
		{"10.0.1.1/24", "10.0.1.0/24"},
		{"::1", "::1/128"},
		{"2002::1/64", "2002::/64"},
	}
	for _, test := range tests {
		err := a.ParseCIDR(test.address)
		assert.NoError(t, err)

		assert.Equal(t, test.str, a.String())
		assert.True(t, a.Mask())
	}
}

func TestAnyIP(t *testing.T) {
	a := newAddress()
	// by default any new address is an "any" address
	assert.True(t, a.Any())
	assert.Equal(t, "any", a.String())

	// set addressmask
	err := a.ParseCIDR("10.0.1.0/24")
	assert.NoError(t, err)
	assert.Equal(t, "10.0.1.0/24", a.String())

	// check that SetAny works
	assert.False(t, a.Any())
	a.SetAny()
	assert.True(t, a.Any())
	assert.Equal(t, "any", a.String())
}

func TestURPFNoRoute(t *testing.T) {
	a := newAddress()
	assert.False(t, a.URPFFailed())
	a.SetURPFFailed()
	assert.True(t, a.URPFFailed())
	assert.Equal(t, "urpf-failed", a.String())

	a = newAddress()
	assert.False(t, a.NoRoute())
	a.SetNoRoute()
	assert.True(t, a.NoRoute())
	assert.Equal(t, "no-route", a.String())
}

func TestRange(t *testing.T) {
	a := newAddress()
	assert.False(t, a.Range())
	a.SetIPRange(net.ParseIP("10.0.1.1"),
		net.ParseIP("10.0.1.200"))
	assert.True(t, a.Range())
	assert.Equal(t, "10.0.1.1 - 10.0.1.200", a.String())
}

func TestTable(t *testing.T) {
	a := newAddress()
	assert.Equal(t, "", a.TableName())
	assert.False(t, a.Table())
	err := a.SetTableName("foobar")
	assert.NoError(t, err)
	assert.True(t, a.Table())
	assert.Equal(t, "foobar", a.TableName())
	assert.Equal(t, "<foobar>", a.String())
	assert.Equal(t, 0, a.TableCount())
}

func TestInterfaceDynamic(t *testing.T) {
	a := newAddress()
	assert.False(t, a.Dynamic())
	assert.Equal(t, "", a.Interface())
	assert.False(t, a.DynamicFlag(DynamicFlagPeer))
	assert.False(t, a.DynamicFlag(DynamicFlagNoAlias))
	assert.False(t, a.DynamicFlag(DynamicFlagNetwork))
	assert.False(t, a.DynamicFlag(DynamicFlagBroadcast))
	assert.Equal(t, 0, a.DynamicCount())

	a.SetInterface("em0")
	tests := []struct {
		flags DynamicFlag
		str   string
	}{
		{DynamicFlagPeer, "(em0:peer)"},
		{DynamicFlagNoAlias, "(em0:0)"},
		{DynamicFlagNetwork, "(em0:network)"},
		{DynamicFlagBroadcast, "(em0:broadcast)"},
		{DynamicFlagPeer | DynamicFlagNoAlias, "(em0:peer:0)"},
		{DynamicFlagNetwork | DynamicFlagNoAlias, "(em0:network:0)"},
		{DynamicFlagNetwork | DynamicFlagNoAlias | DynamicFlagBroadcast | DynamicFlagPeer,
			"(em0:network:broadcast:peer:0)"},
	}
	for _, test := range tests {
		a.SetDynamicFlag(test.flags)

		assert.True(t, a.Dynamic())
		assert.True(t, a.DynamicFlag(test.flags))
		assert.Equal(t, test.str, a.String())
	}
	assert.Equal(t, "em0", a.Interface())
	assert.Equal(t, 0, a.DynamicCount())
}
