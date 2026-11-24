// Package owner routes each asset to the team responsible for it.
//
// Routing is what turns a report into work. The default is deliberately
// "unowned" rather than a guess: an asset that no rule claims is a governance
// finding in its own right, and silently assigning it to a platform team hides
// the gap. Partner-hosted assets get an explicit escalation note, because the
// team that must act on them is not the team that can fix the server.
package owner

import (
	"strings"

	"asm/internal/config"
	"asm/internal/model"
)

// Router assigns owners.
type Router struct {
	cfg *config.Config
}

// NewRouter builds a router.
func NewRouter(cfg *config.Config) *Router { return &Router{cfg: cfg} }

// Route returns the owner for a snapshot.
func (r *Router) Route(s *model.Snapshot) model.Owner {
	var tags []string
	var ports []int
	var tech []string
	for _, svc := range s.Services {
		ports = append(ports, svc.Port)
		if svc.HTTP != nil {
			tech = append(tech, svc.HTTP.Tech...)
		}
	}
	tags = tagsFor(s)

	rule := r.cfg.OwnerRule(s.Host.Name, string(s.Attribution.Class), tags, ports, tech)
	if rule != nil {
		o := model.Owner{Team: rule.Team, Contact: rule.Contact, Source: "rule:" + rule.Name, Rule: rule.Name}
		if o.Contact == "" {
			o.Contact = r.cfg.Owners.DefaultContact
		}
		if rule.Escalation != "" {
			o.Escalation = rule.Escalation
		} else {
			o.Escalation = r.escalationFor(s)
		}
		return o
	}

	o := model.Owner{
		Team:    r.cfg.Owners.DefaultTeam,
		Contact: r.cfg.Owners.DefaultContact,
		Source:  "default",
	}
	o.Escalation = r.escalationFor(s)
	return o
}

// tagsFor derives the tags that owner rules can match on.
func tagsFor(s *model.Snapshot) []string {
	var tags []string
	h := s.Host.Name
	for _, part := range strings.Split(h, ".") {
		switch strings.ToLower(part) {
		case "dev", "test", "staging", "stage", "uat", "qa", "demo", "sandbox", "beta", "pre":
			tags = append(tags, "nonprod")
		case "prod", "www", "api":
			tags = append(tags, "prod")
		}
	}
	if s.Attribution.Class == model.ClassPartner {
		tags = append(tags, "partner")
	}
	if s.Attribution.Class == model.ClassThirdParty {
		tags = append(tags, "cloud")
	}
	return tags
}

func (r *Router) escalationFor(s *model.Snapshot) string {
	switch s.Attribution.Class {
	case model.ClassPartner:
		return "Partner-managed asset: raise a ticket with the vendor's named contact and track the fix there; do not attempt to remediate directly."
	case model.ClassThirdParty:
		return "Cloud/CDN-hosted: confirm the account owner in the cloud console before change; some controls (WAF, TLS) may sit with the platform team."
	case model.ClassWildcard:
		return "Wildcard artefact: verify with a real name before assigning work."
	default:
		return ""
	}
}
