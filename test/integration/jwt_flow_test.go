//go:build integration

// Integration tests for the JWT-related HANA client code paths. Run against a
// live HANA Cloud instance using `make` doesn't apply here; invoke via:
//
//	HANA_BINDINGS="$(cat .claude/hana-bindings.json)" \
//	  go test -tags=integration -v -count=1 ./internal/clients/hana/...
//
// The tests reproduce the §6-§8 sequence from tmp/jwt-setup/TUTORIAL.md:
//   1. Import an IAS-style RSA public key (CREATE PUBLIC KEY).
//   2. Wrap it in a PSE with PURPOSE JWT.
//   3. Declare a JWT PROVIDER and bind the PSE to it.
//   4. Create a restricted user with JWT identity + CLIENT CONNECT.
//   5. Add a HAS MEMBER claim filter; verify it survives Read.
//   6. Reverse everything in dependency order.
//
// We use a self-signed RSA public key (not the real IAS one) so the test does
// not require network access to the IAS canary; HANA only verifies key shape
// on import, not signature against any token.

package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/logging"

	adminv1alpha1 "github.com/SAP/crossplane-provider-hana/apis/admin/v1alpha1"
	"github.com/SAP/crossplane-provider-hana/internal/clients/hana"
	"github.com/SAP/crossplane-provider-hana/internal/clients/hana/jwtprovider"
	"github.com/SAP/crossplane-provider-hana/internal/clients/hana/personalsecurityenvironment"
	"github.com/SAP/crossplane-provider-hana/internal/clients/hana/publickey"
	"github.com/SAP/crossplane-provider-hana/internal/clients/hana/user"
	"github.com/SAP/crossplane-provider-hana/internal/clients/xsql"
)

const (
	testPublicKeyName  = "INTEG_JWT_KEY"
	testPSEName        = "INTEG_JWT_PSE"
	testJWTProviderNm  = "INTEG_JWT_PROVIDER"
	testJWTIssuer      = "https://integ.example.invalid"
	testUserName       = "INTEG_JWT_USER"
	testRoleName       = "INTEG_JWT_ROLE"
	testGroupSCIMUUID  = "00000000-0000-0000-0000-deadbeefcafe"
	testExternalIdent  = "integ-user@example.invalid"
	testApplicationCID = "azp"
)

// rsaPEM builds a fresh self-signed RSA public key in PEM form so the test
// neither depends on a fixture file nor on network access.
func rsaPEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// connect dials HANA using the bindings JSON the /hana up workflow drops in
// .claude/. Skip cleanly when HANA_BINDINGS is missing.
func mustConnect(t *testing.T) (context.Context, xsql.DB, context.CancelFunc, func() error) {
	t.Helper()
	bindings := os.Getenv("HANA_BINDINGS")
	if bindings == "" {
		t.Skip("HANA_BINDINGS not set; run /hana up first then export HANA_BINDINGS=\"$(cat .claude/hana-bindings.json)\"")
	}
	var creds map[string]string
	if err := json.Unmarshal([]byte(bindings), &creds); err != nil {
		t.Fatalf("HANA_BINDINGS not valid JSON: %v", err)
	}
	credBytes := make(map[string][]byte, len(creds))
	for k, v := range creds {
		credBytes[k] = []byte(v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	connector := hana.New(logging.NewNopLogger())
	db, err := connector.Connect(ctx, credBytes)
	if err != nil {
		cancel()
		t.Fatalf("hana.Connect: %v", err)
	}
	return ctx, db, cancel, connector.Disconnect
}

func cleanupAll(t *testing.T, ctx context.Context, db xsql.DB) {
	t.Helper()
	// Best-effort, ignore errors: this runs before the test starts and again
	// at the end so that a previously-failed run cannot wedge subsequent
	// runs. Order matters: drop user before role; drop PSE before provider;
	// drop public key last.
	stmts := []string{
		fmt.Sprintf("DROP USER %s CASCADE", testUserName),
		fmt.Sprintf("DROP ROLE %s", testRoleName),
		fmt.Sprintf("DROP JWT PROVIDER %s", testJWTProviderNm),
		fmt.Sprintf("DROP PSE %s", testPSEName),
		fmt.Sprintf("DROP PUBLIC KEY %s", testPublicKeyName),
	}
	for _, s := range stmts {
		if _, err := db.ExecContext(ctx, s); err != nil {
			t.Logf("cleanup (ok if absent): %s -- %v", s, err)
		}
	}
}

type sqlExec = xsql.DB

// TestIntegrationJWTFlow is the headline test: a single run-through of the
// §6-§8 setup, with each step verified by reading back from SYS views.
func TestIntegrationJWTFlow(t *testing.T) {
	ctx, db, cancel, disconnect := mustConnect(t)
	defer cancel()
	defer func() { _ = disconnect() }()

	pkClient := publickey.New(db)
	pseClient := personalsecurityenvironment.New(db)
	jpClient := jwtprovider.New(db)
	userClient := user.New(db, getCurrentUser(t, ctx, db))

	// Reset state up front.
	cleanupAll(t, ctx, db)

	// ---------------------------------------------------------------------
	// §6 — CREATE PUBLIC KEY + CREATE PSE PURPOSE JWT
	// ---------------------------------------------------------------------
	pemStr := rsaPEM(t)
	pkParams := &adminv1alpha1.PublicKeyParameters{
		Name:    testPublicKeyName,
		PEM:     pemStr,
		Comment: "integration-test key",
	}
	if err := pkClient.Create(ctx, pkParams); err != nil {
		t.Fatalf("PublicKey.Create: %v", err)
	}
	defer func() { _ = pkClient.Delete(ctx, pkParams) }()

	pkObs, err := pkClient.Read(ctx, pkParams)
	if err != nil {
		t.Fatalf("PublicKey.Read after create: %v", err)
	}
	if pkObs == nil || pkObs.Name == nil || *pkObs.Name != testPublicKeyName {
		t.Fatalf("PublicKey.Read returned %+v", pkObs)
	}
	if pkObs.Algorithm == nil || !strings.HasPrefix(*pkObs.Algorithm, "RSA") {
		t.Errorf("expected RSA algorithm, got %v", pkObs.Algorithm)
	}

	pseParams := &adminv1alpha1.PersonalSecurityEnvironmentParameters{
		Name:    testPSEName,
		Purpose: adminv1alpha1.PSEPurposeJWT,
		PublicKeyRefs: []adminv1alpha1.PublicKeyRef{
			{Name: testPublicKeyName},
		},
	}
	// Provider does not exist yet; pass "" to skip the SET PSE PURPOSE step.
	if err := pseClient.Create(ctx, pseParams, ""); err != nil {
		t.Fatalf("PSE.Create: %v", err)
	}
	defer func() { _ = pseClient.Delete(ctx, pseParams) }()

	// ---------------------------------------------------------------------
	// §7 — CREATE JWT PROVIDER, bind PSE
	// ---------------------------------------------------------------------
	priority := 100
	jpParams := &adminv1alpha1.JWTProviderParameters{
		Name:                    testJWTProviderNm,
		Issuer:                  testJWTIssuer,
		ExternalIdentityClaim:   "sub",
		CaseInsensitiveIdentity: true,
		ApplicationUserClaim:    testApplicationCID,
		Priority:                &priority,
		ClaimFilters: []adminv1alpha1.JWTClaimFilter{
			{Claim: "groups", Value: testGroupSCIMUUID},
		},
	}
	if err := jpClient.Create(ctx, jpParams); err != nil {
		t.Fatalf("JWTProvider.Create: %v", err)
	}
	defer func() { _ = jpClient.Delete(ctx, jpParams) }()

	jpObs, err := jpClient.Read(ctx, jpParams)
	if err != nil {
		t.Fatalf("JWTProvider.Read: %v", err)
	}
	if jpObs == nil || jpObs.Issuer == nil || *jpObs.Issuer != testJWTIssuer {
		t.Fatalf("JWTProvider observation issuer wrong: %+v", jpObs)
	}
	if jpObs.ApplicationUserClaim != testApplicationCID {
		t.Errorf("APPLICATION USER claim: want %q got %q", testApplicationCID, jpObs.ApplicationUserClaim)
	}
	if len(jpObs.ClaimFilters) != 1 || jpObs.ClaimFilters[0].Claim != "groups" || jpObs.ClaimFilters[0].Value != testGroupSCIMUUID {
		t.Errorf("HAS MEMBER filter not echoed back: %+v", jpObs.ClaimFilters)
	}

	// Now wire the PSE to the provider with SET PSE PURPOSE JWT FOR PROVIDER.
	if err := pseClient.Update(ctx, pseParams.Name, adminv1alpha1.PSEPurposeJWT, nil, nil, nil, nil, testJWTProviderNm); err != nil {
		t.Fatalf("PSE.Update (bind to JWT provider): %v", err)
	}

	pseObs, err := pseClient.Read(ctx, pseParams)
	if err != nil {
		t.Fatalf("PSE.Read: %v", err)
	}
	if pseObs == nil {
		t.Fatalf("PSE.Read returned nil after create")
	}
	if pseObs.JWTProviderName != testJWTProviderNm {
		t.Errorf("PSE.JWTProviderName: want %q got %q", testJWTProviderNm, pseObs.JWTProviderName)
	}
	foundKey := false
	for _, k := range pseObs.PublicKeys {
		if k == testPublicKeyName {
			foundKey = true
			break
		}
	}
	if !foundKey {
		t.Errorf("PSE.PublicKeys does not contain %q: %v", testPublicKeyName, pseObs.PublicKeys)
	}

	// ---------------------------------------------------------------------
	// §8 — Role + restricted user + JWT identity + CLIENT CONNECT
	// ---------------------------------------------------------------------
	if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE ROLE %s", testRoleName)); err != nil {
		t.Fatalf("CREATE ROLE: %v", err)
	}
	defer func() { _, _ = db.ExecContext(ctx, fmt.Sprintf("DROP ROLE %s", testRoleName)) }()

	if _, err := db.ExecContext(ctx, fmt.Sprintf("GRANT CATALOG READ TO %s", testRoleName)); err != nil {
		t.Fatalf("GRANT CATALOG READ: %v", err)
	}

	userParams := &adminv1alpha1.UserParameters{
		Username:                       testUserName,
		RestrictedUser:                 true,
		IsPasswordLifetimeCheckEnabled: false,
		EnableClientConnect:            true,
		Authentication: adminv1alpha1.Authentication{
			JWTProviders: []adminv1alpha1.JWTUserMapping{
				{
					JWTProviderRef:   adminv1alpha1.JWTProviderRef{Name: testJWTProviderNm},
					ExternalIdentity: testExternalIdent,
				},
			},
		},
		Roles: []string{`"` + testRoleName + `"`},
	}
	jwtMappings := []user.ResolvedJWTUserMapping{
		{Name: testJWTProviderNm, ExternalIdentity: testExternalIdent},
	}
	if err := userClient.Create(ctx, userParams, "", nil, jwtMappings); err != nil {
		t.Fatalf("User.Create: %v", err)
	}
	defer func() { _ = userClient.Delete(ctx, userParams) }()

	userObs, err := userClient.Read(ctx, userParams, "")
	if err != nil {
		t.Fatalf("User.Read: %v", err)
	}
	if userObs.Username == nil || *userObs.Username != testUserName {
		t.Fatalf("User.Read: %+v", userObs)
	}
	if userObs.IsJWTEnabled == nil || !*userObs.IsJWTEnabled {
		t.Errorf("IS_JWT_ENABLED expected true, got %v", userObs.IsJWTEnabled)
	}
	if userObs.IsClientConnectEnabled == nil || !*userObs.IsClientConnectEnabled {
		t.Errorf("IS_CLIENT_CONNECT_ENABLED expected true, got %v", userObs.IsClientConnectEnabled)
	}
	if len(userObs.JWTProviders) != 1 ||
		userObs.JWTProviders[0].Name != testJWTProviderNm ||
		userObs.JWTProviders[0].ExternalIdentity != testExternalIdent {
		t.Errorf("JWT identity mapping not stored: %+v", userObs.JWTProviders)
	}

	// ---------------------------------------------------------------------
	// Drift detection: toggle CLIENT CONNECT off and back on through the
	// dedicated helper, then verify the observation flips.
	// ---------------------------------------------------------------------
	if err := userClient.ToggleClientConnect(ctx, testUserName, false); err != nil {
		t.Fatalf("ToggleClientConnect(false): %v", err)
	}
	userObs, err = userClient.Read(ctx, userParams, "")
	if err != nil {
		t.Fatalf("User.Read after toggle: %v", err)
	}
	if userObs.IsClientConnectEnabled == nil || *userObs.IsClientConnectEnabled {
		t.Errorf("expected CLIENT CONNECT off, got %v", userObs.IsClientConnectEnabled)
	}
	if err := userClient.ToggleClientConnect(ctx, testUserName, true); err != nil {
		t.Fatalf("ToggleClientConnect(true): %v", err)
	}

	// ---------------------------------------------------------------------
	// Claim-filter drift: change the value of the groups filter via Update;
	// observation should reflect the new value, not the old one. HANA's
	// `SET CLAIM '<c>' HAS MEMBER '<v>'` is one-value-per-claim; multiple
	// allowed values per claim are not supported.
	// ---------------------------------------------------------------------
	desired := *jpParams
	desired.ClaimFilters = []adminv1alpha1.JWTClaimFilter{
		{Claim: "groups", Value: "11111111-2222-3333-4444-555555555555"},
	}
	if err := jpClient.Update(ctx, &desired, jpObs); err != nil {
		t.Fatalf("JWTProvider.Update: %v", err)
	}
	jpObs2, err := jpClient.Read(ctx, &desired)
	if err != nil {
		t.Fatalf("JWTProvider.Read after Update: %v", err)
	}
	if len(jpObs2.ClaimFilters) != 1 ||
		jpObs2.ClaimFilters[0].Value != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("after replacing filter value, want 1 filter with new value; got %+v", jpObs2.ClaimFilters)
	}

	// Drop the filter entirely.
	desired2 := *jpParams
	desired2.ClaimFilters = nil
	if err := jpClient.Update(ctx, &desired2, jpObs2); err != nil {
		t.Fatalf("JWTProvider.Update (drop filter): %v", err)
	}
	jpObs3, err := jpClient.Read(ctx, &desired2)
	if err != nil {
		t.Fatalf("JWTProvider.Read after dropping filter: %v", err)
	}
	if len(jpObs3.ClaimFilters) != 0 {
		t.Errorf("after dropping filter, want 0 filters; got %+v", jpObs3.ClaimFilters)
	}
}

func getCurrentUser(t *testing.T, ctx context.Context, db sqlExec) string {
	t.Helper()
	var u string
	if err := db.QueryRowContext(ctx, "SELECT CURRENT_USER FROM DUMMY").Scan(&u); err != nil {
		t.Fatalf("SELECT CURRENT_USER: %v", err)
	}
	return u
}
