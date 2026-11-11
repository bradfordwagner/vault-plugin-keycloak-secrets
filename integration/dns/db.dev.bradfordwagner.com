; Production shape: one A record per cluster, a CNAME users and the engine dial.
$ORIGIN dev.bradfordwagner.com.
$TTL 5
@                  IN SOA ns.dev.bradfordwagner.com. admin.dev.bradfordwagner.com. 1 60 60 60 5
@                  IN NS  ns.dev.bradfordwagner.com.
ns                 IN A   172.30.53.53
keycloak.clustera  IN A   172.30.53.10
keycloak           IN CNAME keycloak.clustera.dev.bradfordwagner.com.
; Admin-only name, pinned as KC_HOSTNAME_ADMIN in hostname-fixed.yml.
keycloak-admin.clustera IN A 172.30.53.10
