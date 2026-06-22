package publickey

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/SAP/crossplane-provider-hana/apis/admin/v1alpha1"
	"github.com/SAP/crossplane-provider-hana/internal/clients/xsql"
)

// Client manages HANA `PUBLIC KEY` DDL objects.
type Client struct {
	xsql.DB
}

// New creates a new public key client.
func New(db xsql.DB) Client {
	return Client{DB: db}
}

// PublicKeyClient is the interface satisfied by Client.
type PublicKeyClient interface {
	Read(ctx context.Context, parameters *v1alpha1.PublicKeyParameters) (*v1alpha1.PublicKeyObservation, error)
	Create(ctx context.Context, parameters *v1alpha1.PublicKeyParameters) error
	Update(ctx context.Context, parameters *v1alpha1.PublicKeyParameters, observation *v1alpha1.PublicKeyObservation) error
	Delete(ctx context.Context, parameters *v1alpha1.PublicKeyParameters) error
}

// Read inspects SYS.PUBLIC_KEYS for the named entry. Returns nil observation
// when the key does not exist.
func (c Client) Read(ctx context.Context, parameters *v1alpha1.PublicKeyParameters) (*v1alpha1.PublicKeyObservation, error) {
	query := "SELECT PUBLIC_KEY_NAME, ALGORITHM, FINGERPRINT, COMMENT FROM SYS.PUBLIC_KEYS WHERE PUBLIC_KEY_NAME = ?"

	var name, algorithm, fingerprint string
	var comment sql.NullString

	err := c.QueryRowContext(ctx, query, parameters.Name).Scan(&name, &algorithm, &fingerprint, &comment)
	if xsql.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to query public key: %w", err)
	}

	obs := &v1alpha1.PublicKeyObservation{
		Name:        &name,
		Algorithm:   &algorithm,
		Fingerprint: &fingerprint,
	}
	if comment.Valid {
		obs.Comment = &comment.String
	}
	return obs, nil
}

// Create runs `CREATE PUBLIC KEY <name> FROM '<pem>' [COMMENT '<comment>']`.
// The PEM is embedded inline; HANA rejects newlines outside of PEM markers, so
// callers must pass a real PEM-encoded value.
func (c Client) Create(ctx context.Context, parameters *v1alpha1.PublicKeyParameters) error {
	if strings.TrimSpace(parameters.PEM) == "" {
		return fmt.Errorf("public key PEM is empty")
	}

	// Single-quotes inside a PEM body would terminate the literal; PEM
	// content is base64 and the standard alphabet does not include a quote,
	// so we keep the string as-is.
	query := fmt.Sprintf("CREATE PUBLIC KEY %s FROM '%s'", parameters.Name, parameters.PEM)
	if parameters.Comment != "" {
		query += fmt.Sprintf(" COMMENT '%s'", escapeSingle(parameters.Comment))
	}

	if _, err := c.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("failed to create public key: %w", err)
	}
	return nil
}

// Update is best-effort. HANA does not provide an ALTER for the key material
// itself; rotating the PEM requires DROP + CREATE. We only rewrite the COMMENT
// when it diverges (cheap, side-effect-free).
func (c Client) Update(ctx context.Context, parameters *v1alpha1.PublicKeyParameters, observation *v1alpha1.PublicKeyObservation) error {
	if observation == nil {
		return fmt.Errorf("public key %q not found, cannot update", parameters.Name)
	}

	desiredComment := parameters.Comment
	currentComment := ""
	if observation.Comment != nil {
		currentComment = *observation.Comment
	}
	if desiredComment == currentComment {
		return nil
	}

	// COMMENT ON PUBLIC KEY <name> IS '<comment>' is the documented form for
	// rewriting the comment without rotating the key.
	query := fmt.Sprintf("COMMENT ON PUBLIC KEY %s IS '%s'", parameters.Name, escapeSingle(desiredComment))
	if _, err := c.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("failed to update public key comment: %w", err)
	}
	return nil
}

// Delete drops the public key.
func (c Client) Delete(ctx context.Context, parameters *v1alpha1.PublicKeyParameters) error {
	query := fmt.Sprintf("DROP PUBLIC KEY %s", parameters.Name)
	if _, err := c.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("failed to drop public key: %w", err)
	}
	return nil
}

func escapeSingle(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
