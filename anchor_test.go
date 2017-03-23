package pf

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAnchorRule(t *testing.T) {
	// invalid ticket
	assert.Error(t, pfh.rule(0, 0, nil))

	// nil rule will panic
	assert.Panics(t, func() {
		pfh.rule(1, 0, nil)
	}, "asd")
}

func TestAnchorRules(t *testing.T) {
	rules, err := pfh.Rules()
	assert.NoError(t, err)
	assert.Empty(t, rules)
}
