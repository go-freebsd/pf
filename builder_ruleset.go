package pf

import (
	"errors"
	"fmt"
)

// Ruleset is an ordered collection of rule builders that is loaded into the
// kernel in one go, the way pfctl -f loads a file: every rule set (scrub,
// nat, binat, rdr, filter) of the anchor is replaced in one transaction, so
// there is never a moment with half of the rules. The rules are sorted into
// their rule sets by kind; the order within a kind is the order of Add.
//
//	err := pf.NewRuleset().
//		Add(pf.NAT().On("em0").RedirectToInterface("em0")).
//		Add(pf.Pass().Out().On("em0")).
//		Load(pfh, "")
type Ruleset struct {
	builders []*RuleBuilder
}

// NewRuleset returns an empty collection.
func NewRuleset() *Ruleset { return &Ruleset{} }

// Add appends rules.
func (rs *Ruleset) Add(rules ...*RuleBuilder) *Ruleset {
	rs.builders = append(rs.builders, rules...)
	return rs
}

// rulesetOrder is the order of the rule sets in the transaction, the order
// pfctl loads them in.
var rulesetOrder = []RuleSetType{RuleSetScrub, RuleSetNAT, RuleSetBINAT, RuleSetRedirect, RuleSetFilter}

// Rules returns the kernel rules by rule set, or all errors of the rules.
func (rs *Ruleset) Rules() (map[RuleSetType][]*Rule, error) {
	out := map[RuleSetType][]*Rule{}
	var errs []error
	for i, b := range rs.builders {
		rules, err := b.Rules()
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %d: %w", i+1, err))
			continue
		}
		out[b.RuleSetType()] = append(out[b.RuleSetType()], rules...)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}

// Load replaces the rules of the anchor ("" for the main rule set) with these,
// atomically. Rule sets without a rule are emptied. Nothing is sent if one of
// the rules is invalid.
func (rs *Ruleset) Load(h *Handle, anchor string) error {
	rules, err := rs.Rules()
	if err != nil {
		return err
	}
	tx := h.NewTransaction(len(rulesetOrder))
	sets := make([]*RuleSet, len(rulesetOrder))
	for i, t := range rulesetOrder {
		set := tx.RuleSet(i)
		set.SetType(t)
		if err := set.SetAnchor(anchor); err != nil {
			return err
		}
		sets[i] = set
	}
	if err := tx.Begin(); err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()
	for i, t := range rulesetOrder {
		for _, r := range rules[t] {
			if err := sets[i].AddRule(r); err != nil {
				return fmt.Errorf("%s: %w", r, err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	committed = true
	return nil
}
