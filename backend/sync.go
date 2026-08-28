package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/logical"
)

// cloneRecord tracks a live clone (one per lease) so upstream syncs can find and
// update it. Records live under clones/<realm>/<role>/<internal_id> and are
// written at mint (path_creds) and deleted at revoke (secret_client).
type cloneRecord struct {
	CloneClientID string `json:"clone_client_id"`
	InternalID    string `json:"internal_id"`
}

// syncState remembers the last-synced hash of a role's source client so the
// periodic pass only touches clones when the source actually changed. Stored
// under syncstate/<realm>/<role>.
type syncState struct {
	SourceHash string `json:"source_hash"`
}

func cloneRecordDir(realm, role string) string {
	return fmt.Sprintf("clones/%s/%s/", realm, role)
}

func cloneRecordKey(realm, role, internalID string) string {
	return cloneRecordDir(realm, role) + internalID
}

func syncStateKey(realm, role string) string {
	return fmt.Sprintf("syncstate/%s/%s", realm, role)
}

func writeCloneRecord(ctx context.Context, s logical.Storage, realm, role string, rec cloneRecord) error {
	entry, err := logical.StorageEntryJSON(cloneRecordKey(realm, role, rec.InternalID), rec)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func deleteCloneRecord(ctx context.Context, s logical.Storage, realm, role, internalID string) error {
	return s.Delete(ctx, cloneRecordKey(realm, role, internalID))
}

func listCloneRecords(ctx context.Context, s logical.Storage, realm, role string) ([]cloneRecord, error) {
	dir := cloneRecordDir(realm, role)
	ids, err := s.List(ctx, dir)
	if err != nil {
		return nil, err
	}
	recs := make([]cloneRecord, 0, len(ids))
	for _, id := range ids {
		entry, err := s.Get(ctx, dir+id)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			continue
		}
		var rec cloneRecord
		if err := entry.DecodeJSON(&rec); err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

func readSyncState(ctx context.Context, s logical.Storage, realm, role string) (syncState, error) {
	var st syncState
	entry, err := s.Get(ctx, syncStateKey(realm, role))
	if err != nil {
		return st, err
	}
	if entry == nil {
		return st, nil
	}
	if err := entry.DecodeJSON(&st); err != nil {
		return st, err
	}
	return st, nil
}

func writeSyncState(ctx context.Context, s logical.Storage, realm, role string, st syncState) error {
	entry, err := logical.StorageEntryJSON(syncStateKey(realm, role), st)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

// hashRep returns a stable sha256 of a client representation. encoding/json
// marshals map keys in sorted order, so the digest is deterministic for a given
// representation.
func hashRep(m map[string]interface{}) (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// syncUpstream walks every role in every realm and, for those with
// sync_upstream enabled, propagates changes from the source (template) client
// onto that role's live clones. It is best-effort: per-role failures are logged
// and skipped so one broken role never blocks the others (or the periodic tick).
func (b *backend) syncUpstream(ctx context.Context, s logical.Storage) error {
	cfg, err := getConfig(ctx, s)
	if err != nil {
		return err
	}
	if cfg == nil || !cfg.isConfigured() {
		return nil
	}

	realms, err := s.List(ctx, "realm/")
	if err != nil {
		return err
	}

	for _, r := range realms {
		realm := strings.TrimSuffix(r, "/")
		if realm == "" {
			continue
		}
		roleNames, err := s.List(ctx, rolesStoragePrefix(realm))
		if err != nil {
			b.Logger().Warn("upstream sync: failed to list roles", "realm", realm, "error", err)
			continue
		}
		for _, roleName := range roleNames {
			role, err := getRole(ctx, s, realm, roleName)
			if err != nil {
				b.Logger().Warn("upstream sync: failed to load role", "realm", realm, "role", roleName, "error", err)
				continue
			}
			if role == nil || !role.SyncUpstream {
				continue
			}
			if err := b.syncRoleClones(ctx, s, cfg, realm, roleName, role); err != nil {
				b.Logger().Warn("upstream sync: role sync failed", "realm", realm, "role", roleName, "error", err)
			}
		}
	}
	return nil
}

// syncRoleClones detects whether a role's source client changed since the last
// pass and, if so, updates all of that role's live clones to match. Each clone's
// clientId and client_secret are preserved (the PUT body carries no secret), so
// existing leases keep working. Service-account role mappings are re-copied
// additively (new upstream grants propagate; removals do not).
func (b *backend) syncRoleClones(ctx context.Context, s logical.Storage, cfg *config, realm, roleName string, role *keycloakRole) error {
	client, err := newKeycloakClient(cfg, realm)
	if err != nil {
		return err
	}
	token, err := client.token(ctx)
	if err != nil {
		return fmt.Errorf("failed to obtain admin token: %w", err)
	}

	sourceInternalID, err := client.getClientByClientID(ctx, token, role.SourceClientID)
	if err != nil {
		return fmt.Errorf("failed to look up source client %q: %w", role.SourceClientID, err)
	}
	srcRaw, err := client.getClientRaw(ctx, token, sourceInternalID)
	if err != nil {
		return fmt.Errorf("failed to fetch source client %q: %w", role.SourceClientID, err)
	}

	hash, err := hashRep(srcRaw)
	if err != nil {
		return err
	}
	st, err := readSyncState(ctx, s, realm, roleName)
	if err != nil {
		return err
	}
	if st.SourceHash == hash {
		// Source unchanged since the last successful sync — nothing to do.
		return nil
	}

	recs, err := listCloneRecords(ctx, s, realm, roleName)
	if err != nil {
		return err
	}

	// Read the source service account's role mappings once, to re-copy onto each
	// clone. Only meaningful when the source has a service account.
	var srcMappings *roleMappings
	srcHasServiceAccount, _ := srcRaw["serviceAccountsEnabled"].(bool)
	if srcHasServiceAccount {
		if srcSA, err := client.serviceAccountUserID(ctx, token, sourceInternalID); err == nil {
			srcMappings, _ = client.userRoleMappings(ctx, token, srcSA)
		}
	}

	for _, rec := range recs {
		rep := buildSyncRepresentation(srcRaw, rec.CloneClientID, rec.InternalID)
		// The sync rep is built from the source client, which carries neither the
		// clone's tracking description nor its vkp.* attributes (provenance +
		// lease linkage). Re-apply them from the clone's current representation so
		// the sync never clobbers a clone's trace metadata.
		if cloneRaw, err := client.getClientRaw(ctx, token, rec.InternalID); err == nil {
			preserveTracking(rep, cloneRaw)
		} else {
			b.Logger().Warn("upstream sync: failed to fetch clone for tracking preservation", "clone", rec.CloneClientID, "error", err)
		}
		if err := client.updateClientRaw(ctx, token, rec.InternalID, rep); err != nil {
			b.Logger().Warn("upstream sync: failed to update clone", "clone", rec.CloneClientID, "error", err)
			continue
		}
		if srcHasServiceAccount && srcMappings != nil {
			cloneSA, err := client.serviceAccountUserID(ctx, token, rec.InternalID)
			if err != nil {
				b.Logger().Warn("upstream sync: failed to resolve clone service account", "clone", rec.CloneClientID, "error", err)
				continue
			}
			if len(srcMappings.RealmMappings) > 0 {
				if err := client.assignRealmRoles(ctx, token, cloneSA, srcMappings.RealmMappings); err != nil {
					b.Logger().Warn("upstream sync: failed to copy realm role mappings", "clone", rec.CloneClientID, "error", err)
				}
			}
			for _, entry := range srcMappings.ClientMappings {
				if err := client.assignClientRoles(ctx, token, cloneSA, entry.ID, entry.Mappings); err != nil {
					b.Logger().Warn("upstream sync: failed to copy client role mappings", "clone", rec.CloneClientID, "client", entry.Client, "error", err)
				}
			}
		}
	}

	// Record the new hash so the next pass is a no-op until the source changes
	// again. Recorded even when there are zero clones, so an idle role does not
	// re-scan every tick.
	return writeSyncState(ctx, s, realm, roleName, syncState{SourceHash: hash})
}
