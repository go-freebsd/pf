package pf

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEmptyRuleString(t *testing.T) {
	var rule Rule
	assert.Equal(t, "pass inout from any to any", rule.String())
	assert.False(t, rule.Log())
	assert.False(t, rule.Quick())
	assert.Equal(t, ProtocolAny, rule.Protocol())
	assert.Equal(t, AddressFamilyAny, rule.AddressFamily())
}

func TestParsing(t *testing.T) {
	cases := [][]string{
		[]string{
			"10.0.0.1",
			"10",
			"10.0.0.255",
			"!=10",
			"pass inout inet from 10.0.0.1/32 port 10 to 10.0.0.255/32 port !=10",
		},
		[]string{
			"10.0.0.1/0",
			">10",
			"10.0.1.255/24",
			"<10",
			"pass inout inet from 0.0.0.0/0 port >10 to 10.0.1.0/24 port <10",
		},
		[]string{
			"10.0.0.1",
			">=10",
			"10.0.0.255",
			"<=10",
			"pass inout inet from 10.0.0.1/32 port >=10 to 10.0.0.255/32 port <=10",
		},
		[]string{
			"::1",
			"1<>10",
			"2002::1",
			"10><100",
			"pass inout inet6 from ::1/128 port 1<>10 to 2002::1/128 port 10><100",
		},
		[]string{
			"2001::1/64",
			"1<>10",
			"2002::1/64",
			"10><100",
			"pass inout inet6 from 2001::/64 port 1<>10 to 2002::/64 port 10><100",
		},
	}

	for _, tc := range cases {
		var rule Rule

		assert.NoError(t, rule.ParseSource(tc[0], tc[1], false))
		assert.NoError(t, rule.ParseDestination(tc[2], tc[3], false))
		assert.Equal(t, tc[4], rule.String())
	}
}

func TestParsingErrors(t *testing.T) {
	cases := []string{
		"1 2 3",
		"-123",
		"123123123",
		"12!",
		"!2",
		"123a",
		">a",
		"<a",
	}

	for _, tc := range cases {
		var rule Rule

		assert.Error(t, rule.ParseSource("10.0.0.1", tc, false),
			fmt.Sprintf("Expected errors fo '%s'", tc))
	}
}

func TestNegativeRules(t *testing.T) {
	var rule Rule
	assert.NoError(t, rule.ParseSource("10.0.1.1", "10", true))
	assert.NoError(t, rule.ParseDestination("10.0.2.1", "10", true))
	assert.Equal(t, "pass inout inet from ! 10.0.1.1/32 port 10 to ! 10.0.2.1/32 port 10", rule.String())
}
