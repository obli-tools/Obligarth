package mdm

import (
	"github.com/MeeJay/Obligarth/apple-edge/internal/config"
	"github.com/MeeJay/Obligarth/apple-edge/internal/store"
)

// Outcomes of a device identifier conflict, as seen by each tenant.
const (
	OutcomeRefused     = "refused"
	OutcomeKept        = "kept"
	OutcomeSuperseded  = "superseded"
	OutcomeTransferred = "transferred"
)

// Decision is the result of the cross-tenant policy at Authenticate.
type Decision struct {
	Accept           bool
	Conflict         bool   // another tenant held the identifier (alerts)
	ReleaseReason    string // release of the holder's identifier, if any
	DisableHolder    bool   // disable the holder's enrollment and clear its queue
	RequesterOutcome string
	HolderOutcome    string
	Transfer         *store.Transfer
}

// Decide applies the matrix of the cross-tenant policy for an identifier
// presented by requester at Authenticate:
//
//   - unknown, or active in the requester: accept;
//   - an EnrollmentID active elsewhere: refuse (it is random per enrollment);
//   - an approved transfer holder -> requester: accept, holder released and disabled;
//   - ADE proof in the requester: accept, holder released and disabled;
//   - policy refuse: refuse, holder kept;
//   - policy allow: accept, holder released (superseded) without disabling.
func Decide(requester, kind, proof, policy string, holder *store.ActiveID, transfer *store.Transfer) Decision {
	if holder == nil || holder.Tenant == requester {
		return Decision{Accept: true}
	}
	d := Decision{Conflict: true}
	switch {
	case kind == store.KindEnrollmentID:
		d.RequesterOutcome, d.HolderOutcome = OutcomeRefused, OutcomeKept
	case transfer != nil:
		d.Accept, d.ReleaseReason, d.DisableHolder, d.Transfer = true, "transfer", true, transfer
		d.RequesterOutcome, d.HolderOutcome = OutcomeTransferred, OutcomeTransferred
	case proof == store.ProofADE:
		d.Accept, d.ReleaseReason, d.DisableHolder = true, "superseded_by_proof", true
		d.RequesterOutcome, d.HolderOutcome = OutcomeSuperseded, OutcomeSuperseded
	case policy == config.PolicyAllow:
		d.Accept, d.ReleaseReason = true, "superseded"
		d.RequesterOutcome, d.HolderOutcome = OutcomeSuperseded, OutcomeSuperseded
	default:
		d.RequesterOutcome, d.HolderOutcome = OutcomeRefused, OutcomeKept
	}
	return d
}
