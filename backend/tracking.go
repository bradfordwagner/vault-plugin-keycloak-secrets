package backend

import (
	"fmt"
	"strings"
	"time"
)

// pluginName is the canonical plugin name stamped onto every clone for
// provenance.
const pluginName = "vault-plugin-keycloak-secrets"

// vkp.* clone-tracking attribute keys. These are written onto every clone's
// Keycloak attributes at mint and preserved across upstream syncs, so a clone is
// always traceable back to this plugin and the template it was cloned from. The
// vkp. prefix namespaces them and is what preserveTracking keys off of.
//
// There is intentionally no lease-id attribute: Vault never hands a backend its
// own lease id (SDK logical.Secret.LeaseID is always blank on a request), so a
// clone cannot record the lease that owns it. A clone is instead traced back to
// its lease out-of-band via vkp.creds_path.
const (
	trackAttrManaged      = "vkp.managed"          // "true" — this client is vkp-managed
	trackAttrPlugin       = "vkp.plugin"           // plugin name that created it
	trackAttrSourceClient = "vkp.source_client_id" // clientId of the template it was cloned from
	trackAttrMount        = "vkp.mount"            // Vault mount path (e.g. "keycloak/")
	trackAttrRealm        = "vkp.realm"            // Keycloak realm
	trackAttrRole         = "vkp.role"             // Vault role name
	trackAttrCreated      = "vkp.created"          // RFC3339 UTC mint time
	trackAttrTTL          = "vkp.ttl"              // role default lease TTL
	trackAttrMaxTTL       = "vkp.max_ttl"          // role maximum lease TTL
	trackAttrMaxExpiry    = "vkp.max_expiry"       // RFC3339 UTC created+max_ttl (latest possible deletion)
	trackAttrCredsPath    = "vkp.creds_path"       // Vault path whose read issued this clone
)

// trackingInfo is the set of trace values known when a clone is minted.
type trackingInfo struct {
	SourceClientID string
	Mount          string
	Realm          string
	Role           string
	CredsPath      string
	Created        time.Time
	TTL            time.Duration
	MaxTTL         time.Duration
}

// attributes renders the vkp.* attribute map for a clone. Zero-valued optional
// fields (ttl/max_ttl) are omitted rather than written blank.
func (t trackingInfo) attributes() map[string]string {
	attrs := map[string]string{
		trackAttrManaged:      "true",
		trackAttrPlugin:       pluginName,
		trackAttrSourceClient: t.SourceClientID,
		trackAttrMount:        t.Mount,
		trackAttrRealm:        t.Realm,
		trackAttrRole:         t.Role,
		trackAttrCreated:      t.Created.UTC().Format(time.RFC3339),
		trackAttrCredsPath:    t.CredsPath,
	}
	if t.TTL > 0 {
		attrs[trackAttrTTL] = t.TTL.String()
	}
	if t.MaxTTL > 0 {
		attrs[trackAttrMaxTTL] = t.MaxTTL.String()
		attrs[trackAttrMaxExpiry] = t.Created.Add(t.MaxTTL).UTC().Format(time.RFC3339)
	}
	return attrs
}

// keycloakDescriptionMax is Keycloak's storage limit for a client description:
// the CLIENT.DESCRIPTION column is varchar(255), and exceeding it makes the
// client create/update fail with a Postgres "value too long for type character
// varying(255)" 500. The description is therefore a BOUNDED human-readable
// summary; the full, untruncated tracking metadata (created, max expiry, creds
// path, lease id, …) always lives in the vkp.* attributes, which are stored in a
// far larger column, so nothing is lost by keeping this short.
const keycloakDescriptionMax = 255

// srcClientIDInDescMax bounds how much of the (source-controlled, variable
// length) template client id is rendered inline in the description, so the
// fixed, high-value facts below it (created time, expiry) always fit within
// keycloakDescriptionMax and are never the part that gets truncated away. The
// full, untruncated id is always available in the vkp.source_client_id
// attribute.
const srcClientIDInDescMax = 48

// description renders the human-readable clone description: that the client is
// vkp-managed, the template it clones, its owning Vault role, WHEN it was
// created, WHEN it expires (created+max_ttl, i.e. the latest possible deletion),
// and the "do not touch" warning. It is hard-capped at keycloakDescriptionMax
// runes so an unusually long source client id / realm / role can never overflow
// Keycloak's varchar(255) column. The owning Vault lease id is intentionally
// NOT rendered here — Vault never hands a backend its own lease id (SDK
// logical.Secret.LeaseID is always blank on a request), so it is unknowable to
// the plugin; a clone is traced to its lease out-of-band via vkp.creds_path. The
// exhaustive detail (creds path, mount, timestamps) lives in the vkp.* attributes.
func (t trackingInfo) description() string {
	src := t.SourceClientID
	if r := []rune(src); len(r) > srcClientIDInDescMax {
		src = string(r[:srcClientIDInDescMax-1]) + "…"
	}
	expiry := "no max_ttl (expiry bounded by the Vault lease)"
	if t.MaxTTL > 0 {
		expiry = "expires by " + t.Created.Add(t.MaxTTL).UTC().Format(time.RFC3339)
	}
	desc := fmt.Sprintf(
		"Managed by %s (vkp): clone of %q for Vault role %s/%s. "+
			"Created %s; %s. "+
			"DO NOT edit or use directly — deleted on Vault lease revoke. "+
			"Details in vkp.* attrs.",
		pluginName,
		src,
		t.Realm, t.Role,
		t.Created.UTC().Format(time.RFC3339),
		expiry,
	)
	if r := []rune(desc); len(r) > keycloakDescriptionMax {
		desc = string(r[:keycloakDescriptionMax-1]) + "…"
	}
	return desc
}

// trackingFromAttributes reconstructs a trackingInfo from a clone's stored vkp.*
// attributes. Unparseable/absent values yield their zero value. Used to
// regenerate a consistent description + attribute set from a clone's own stored
// attributes, without needing any state beyond the clone itself.
func trackingFromAttributes(attrs map[string]interface{}) trackingInfo {
	get := func(k string) string {
		s, _ := attrs[k].(string)
		return s
	}
	info := trackingInfo{
		SourceClientID: get(trackAttrSourceClient),
		Mount:          get(trackAttrMount),
		Realm:          get(trackAttrRealm),
		Role:           get(trackAttrRole),
		CredsPath:      get(trackAttrCredsPath),
	}
	if v, err := time.Parse(time.RFC3339, get(trackAttrCreated)); err == nil {
		info.Created = v
	}
	if d, err := time.ParseDuration(get(trackAttrTTL)); err == nil {
		info.TTL = d
	}
	if d, err := time.ParseDuration(get(trackAttrMaxTTL)); err == nil {
		info.MaxTTL = d
	}
	return info
}

// applyTracking stamps the tracking description and merges the vkp.* attributes
// onto a client representation. Existing (source-derived) attributes are kept;
// the vkp.* keys and description are (over)written. Used at mint.
func applyTracking(rep map[string]interface{}, info trackingInfo) {
	rep["description"] = info.description()
	attrs := attrMap(rep["attributes"])
	for k, v := range info.attributes() {
		attrs[k] = v
	}
	rep["attributes"] = attrs
}

// preserveTracking copies the description and the vkp.* attributes from an
// existing clone onto a freshly built sync representation. An upstream sync
// rebuilds a clone from its source (template) client, which carries neither the
// clone's tracking description nor its vkp.* attributes; without this the sync
// would clobber a clone's provenance. Non-vkp attribute changes from the source
// still propagate.
func preserveTracking(rep, existing map[string]interface{}) {
	if desc, ok := existing["description"].(string); ok && desc != "" {
		rep["description"] = desc
	}
	attrs := attrMap(rep["attributes"])
	for k, v := range attrMap(existing["attributes"]) {
		if strings.HasPrefix(k, "vkp.") {
			attrs[k] = v
		}
	}
	rep["attributes"] = attrs
}

// attrMap coerces a raw client "attributes" value (map[string]interface{} as
// decoded from Keycloak JSON, or nil/absent) into a fresh map[string]interface{}.
func attrMap(v interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	if m, ok := v.(map[string]interface{}); ok {
		for k, val := range m {
			out[k] = val
		}
	}
	return out
}
