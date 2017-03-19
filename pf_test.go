package pf

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStartStop(t *testing.T) {
	err := pfh.Start()
	assert.NoError(t, err)

	err = pfh.Stop()
	assert.NoError(t, err)
}

func TestGetSetStatusInterface(t *testing.T) {
	itfK, err := pfh.StatusInterface()
	assert.NoError(t, err)
	assert.Empty(t, itfK)

	itf := "pflog0"
	err = pfh.SetStatusInterface(itf)
	assert.NoError(t, err)

	itfK, err = pfh.StatusInterface()
	assert.NoError(t, err)

	t.SkipNow()
	assert.Equal(t, itf, itfK)
}

func TestStatistics(t *testing.T) {
	var stats Statistics

	err := pfh.UpdateStatistics(&stats)
	assert.NoError(t, err)

	assert.NotEmpty(t, stats.String())
}

func TestRule(t *testing.T) {
	// invalid ticket
	assert.Error(t, pfh.Rule(0, 0, nil))

	// nil rule will panic
	assert.Panics(t, func() {
		pfh.Rule(1, 0, nil)
	}, "asd")
}

func TestRules(t *testing.T) {
	rules, err := pfh.Rules()
	assert.NoError(t, err)
	assert.Empty(t, rules)
}

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
	assert.Error(t, err)

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
