package store

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/MeeJay/Obligarth/apple-edge/internal/crypto/envelope"
)

// Codes of a refusal caused by the KEK, as in the brain's vault.
const (
	RefusalKEKMismatch   = "kek_mismatch"
	RefusalDecryptFailed = "decrypt_failed"
)

// KEKRefusal is a start-up refusal caused by the KEK. Its messages are the
// brain's (message A: the KEK does not open this database's keys; message B:
// a KEK rotation was interrupted), so that both services share one recovery
// runbook; the commands that meet it exit with code 1, like the brain.
type KEKRefusal struct {
	Code    string
	Message string
}

func (e *KEKRefusal) Error() string { return e.Message }

// printableKEKID makes a kek_id read from the database safe for a log line.
func printableKEKID(id string) string {
	if len(id) > 128 {
		id = id[:128]
	}
	b := []byte(id)
	for i, c := range b {
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte(":/_.-", c) >= 0) {
			b[i] = '?'
		}
	}
	if len(b) == 0 {
		return "(none)"
	}
	return string(b)
}

// KEKMismatchRefusal is message A: the loaded KEK does not open this
// database's keys.
func KEKMismatchRefusal(loaded, expected string) string {
	return fmt.Sprintf("The KEK (kek_id %s) does not open this database's keys (expected kek_id %s). "+
		"Mount the KEK of this database (Docker secret edge_kek, EDGE_KEK_FILE), reconstituted from escrow "+
		"(vault escrow combine), or restore the backup that matches this KEK. Refusing to start.",
		printableKEKID(loaded), printableKEKID(expected))
}

// InterruptedRotationRefusal is message B: data keys wrapped by another KEK
// remain after a KEK rotation that did not finish.
func InterruptedRotationRefusal(other string) string {
	return fmt.Sprintf("Data keys wrapped by another KEK (kek_id %s) remain: a KEK rotation was interrupted. "+
		`Run "apple-edge kek rotate --operation <uuid>" again with EDGE_KEK_PREVIOUS_FILE. Refusing to start.`,
		printableKEKID(other))
}

// KEKFileRefusal is the refusal for a missing or unusable KEK file; cause is
// a fixed text or an error of the file system, never the content of the file.
func KEKFileRefusal(cause string) string {
	return "The KEK file (EDGE_KEK_FILE) is missing or invalid: create it (openssl rand -base64 32), " +
		"readable by the uid of apple-edge (65532), and mount it as the Docker secret edge_kek. Cause: " + cause + "."
}

// CheckKEK verifies, before anything uses the keys, that kek opens this
// database's keys (the canary of the brain's vault): the active instance DEK
// must be wrapped by kek and open with it, and no live DEK may remain under
// another KEK (an interrupted rotation). A new database (no live DEK) passes.
func CheckKEK(ctx context.Context, q Querier, kek *envelope.KEK) error {
	type row struct {
		id, tenant, kekID, state, wrapped string
	}
	rows, err := q.QueryContext(ctx, `
SELECT id, coalesce(tenant_key, ''), kek_id, state, dek_wrapped
  FROM apple_edge.data_keys
 WHERE dek_wrapped IS NOT NULL
 ORDER BY created_at, id`)
	if err != nil {
		return err
	}
	var live []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.tenant, &r.kekID, &r.state, &r.wrapped); err != nil {
			rows.Close()
			return err
		}
		live = append(live, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var active, foreign *row
	underCurrent := false
	for i := range live {
		r := &live[i]
		if r.tenant == "" && r.state == "active" {
			active = r
		}
		if r.kekID == kek.ID() {
			underCurrent = true
		} else if foreign == nil {
			foreign = r
		}
	}
	if active != nil {
		if active.kekID != kek.ID() {
			// Some keys already under the loaded KEK: a rotation stopped half-way.
			if underCurrent {
				return &KEKRefusal{Code: RefusalKEKMismatch, Message: InterruptedRotationRefusal(active.kekID)}
			}
			return &KEKRefusal{Code: RefusalKEKMismatch, Message: KEKMismatchRefusal(kek.ID(), active.kekID)}
		}
		raw, err := kek.Unwrap(active.id, "", active.wrapped)
		if err != nil {
			return &KEKRefusal{Code: RefusalDecryptFailed, Message: KEKMismatchRefusal(kek.ID(), active.kekID)}
		}
		clear(raw)
	}
	if foreign != nil {
		if !underCurrent {
			return &KEKRefusal{Code: RefusalKEKMismatch, Message: KEKMismatchRefusal(kek.ID(), foreign.kekID)}
		}
		return &KEKRefusal{Code: RefusalKEKMismatch, Message: InterruptedRotationRefusal(foreign.kekID)}
	}
	return nil
}

// IsKEKRefusal reports whether err is (or wraps) a refusal caused by the KEK.
func IsKEKRefusal(err error) (*KEKRefusal, bool) {
	var r *KEKRefusal
	if errors.As(err, &r) {
		return r, true
	}
	return nil, false
}
