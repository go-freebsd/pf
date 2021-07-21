package pf

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRuleSetRollback(t *testing.T) {
	var rule Rule
	rule.SetProtocol(ProtocolUDP)
	rule.SetAction(ActionPass)
	err := rule.ParseSource("127.0.0.1", "0:65535", false)
	assert.NoError(t, err)
	err = rule.ParseDestination("8.8.8.8", "53", false)
	assert.NoError(t, err)

	tx := pfh.NewTransaction(1)
	frs := tx.RuleSet(0)
	assert.Equal(t, RuleSetScrub, frs.Type())
	frs.SetType(RuleSetFilter)
	assert.Equal(t, "", frs.Anchor())
	assert.NoError(t, frs.SetAnchor("/asd"))
	assert.Equal(t, "/asd", frs.Anchor())

	err = tx.Begin()
	assert.NoError(t, err)

	err = frs.AddRule(&rule)
	assert.NoError(t, err)

	err = tx.Rollback()
	assert.NoError(t, err)

	rules, err := pfh.Rules()
	assert.NoError(t, err)
	assert.Len(t, rules, 0)
}

func TestAddRuleAndRule(t *testing.T) {
	var rule Rule
	rule.SetProtocol(ProtocolUDP)
	rule.SetLog(true)
	rule.SetQuick(true)
	rule.SetDirection(DirectionIn)
	rule.SetAction(ActionPass)
	rule.SetState(StateKeep)
	err := rule.ParseSource("127.0.0.1", "0:65535", false)
	assert.NoError(t, err)
	err = rule.ParseDestination("8.8.8.8", "53", false)
	assert.NoError(t, err)

	tx := pfh.NewTransaction(1)
	frs := tx.RuleSet(0)
	frs.SetType(RuleSetFilter)

	err = tx.Begin()
	assert.NoError(t, err)

	err = frs.AddRule(&rule)
	assert.NoError(t, err)

	err = tx.Commit()
	assert.NoError(t, err)

	rules, err := pfh.Rules()
	assert.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.Equal(t, "pass in log quick inet proto udp "+
		"from 127.0.0.1/32 port 0:65535 "+
		"to 8.8.8.8/32 port 53 keep state", rules[0].String())
}
