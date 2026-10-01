package store

import (
	"context"
	"time"
)

// ExpiryThreshold returns the most urgent threshold (in days, thresholds
// sorted ascending) that notAfter has crossed at now, 0 once expired, and
// -1 when no threshold is crossed yet.
func ExpiryThreshold(notAfter, now time.Time, thresholds []int) int {
	left := notAfter.Sub(now)
	if left <= 0 {
		return 0
	}
	for _, d := range thresholds {
		if left <= time.Duration(d)*24*time.Hour {
			return d
		}
	}
	return -1
}

// MarkExpiryAlert records that the alert of threshold was emitted for
// subject ("push_cert:<id>" or "ade_token:<id>"); it returns false when it
// already was.
func MarkExpiryAlert(ctx context.Context, q Querier, tenant, subject string, threshold int) (bool, error) {
	res, err := q.ExecContext(ctx, `
INSERT INTO apple_edge.expiry_alerts (tenant_key, subject, threshold) VALUES ($1, $2, $3)
ON CONFLICT (subject, threshold) DO NOTHING`, tenant, subject, threshold)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}
