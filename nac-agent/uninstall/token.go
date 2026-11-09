package uninstall

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Token form of a signed uninstall authorization: base64url (no padding) of the
// exact signed envelope bytes. It carries no extra trust — the same signature,
// device binding, 10-minute window and journal anti-replay checks apply. It
// exists so the authorization can be pasted or read out when the device has no
// path to the eGuard server (e.g. a guest who already left the network).
var ErrToken = errors.New("uninstall token invalid")

const maxToken = 96 * 1024

func EncodeToken(envelope []byte) string { return base64.RawURLEncoding.EncodeToString(envelope) }

func DecodeToken(tok string) ([]byte, error) {
	tok = strings.TrimSpace(tok)
	if tok == "" || len(tok) > maxToken {
		return nil, ErrToken
	}
	b, e := base64.RawURLEncoding.DecodeString(tok)
	if e != nil || !json.Valid(b) {
		return nil, ErrToken
	}
	return b, nil
}
