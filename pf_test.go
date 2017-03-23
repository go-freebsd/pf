package pf

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
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

func TestClearing(t *testing.T) {
	err := pfh.ClearPFStats()
	assert.NoError(t, err)
	err = pfh.ClearSourceNodes()
	assert.NoError(t, err)
	err = pfh.ClearPerRuleStats()
	assert.NoError(t, err)
}

func TestDebugMode(t *testing.T) {
	// default mode is urgent
	var stats Statistics

	err := pfh.UpdateStatistics(&stats)
	assert.NoError(t, err)
	assert.Equal(t, DebugModeUrgent, stats.Debug())

	err = pfh.SetDebugMode(DebugModeNone)
	assert.NoError(t, err)

	err = pfh.UpdateStatistics(&stats)
	assert.NoError(t, err)
	assert.Equal(t, DebugModeNone, stats.Debug())

	err = pfh.SetDebugMode(DebugModeUrgent)
	assert.NoError(t, err)

	err = pfh.UpdateStatistics(&stats)
	assert.NoError(t, err)
	assert.Equal(t, DebugModeUrgent, stats.Debug())
}

func TestHostID(t *testing.T) {
	var stats Statistics

	err := pfh.UpdateStatistics(&stats)
	assert.NoError(t, err)
	oldHost := stats.HostID()

	err = pfh.SetHostID(12345678)
	assert.NoError(t, err)

	err = pfh.UpdateStatistics(&stats)
	assert.NoError(t, err)
	assert.Equal(t, uint32(12345678), stats.HostID())

	err = pfh.SetHostID(oldHost)
	assert.NoError(t, err)

	err = pfh.UpdateStatistics(&stats)
	assert.NoError(t, err)
	assert.Equal(t, oldHost, stats.HostID())
}

func TestTimeouts(t *testing.T) {
	d, err := pfh.Timeout(TimeoutTCPEstablished)
	assert.NoError(t, err)
	assert.Equal(t, time.Hour*24, d)

	err = pfh.SetTimeout(TimeoutTCPEstablished, time.Hour)
	assert.NoError(t, err)

	d, err = pfh.Timeout(TimeoutTCPEstablished)
	assert.NoError(t, err)
	assert.Equal(t, time.Hour, d)

	err = pfh.SetTimeout(TimeoutTCPEstablished, time.Hour*24)
	assert.NoError(t, err)

	d, err = pfh.Timeout(TimeoutTCPEstablished)
	assert.NoError(t, err)
	assert.Equal(t, time.Hour*24, d)
}

func TestLimits(t *testing.T) {
	oldLimit, err := pfh.Limit(LimitTableEntries)
	assert.NoError(t, err)

	err = pfh.SetLimit(LimitTableEntries, 512*1024*1024)
	assert.NoError(t, err)

	limit, err := pfh.Limit(LimitTableEntries)
	assert.NoError(t, err)
	assert.Equal(t, uint(512*1024*1024), limit)

	err = pfh.SetLimit(LimitTableEntries, oldLimit)
	assert.NoError(t, err)

	limit, err = pfh.Limit(LimitTableEntries)
	assert.NoError(t, err)
	assert.Equal(t, oldLimit, limit)
}
