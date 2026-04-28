package integration

import (
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOAuthWithServiceAuth verifies that when a server is configured with both
// the global OAuth provider AND per-server `serviceAuths`, requests authenticated
// via serviceAuths are not rejected by the OAuth validator that runs after the
// service-auth middleware in the chain.
//
// Regression test for the case where Basic credentials matching `serviceAuths`
// would succeed in `NewServiceAuthMiddleware` but then be rejected by
// `NewValidateTokenMiddleware` for not being a Bearer token.
func TestOAuthWithServiceAuth(t *testing.T) {
	cfg := buildTestConfig("http://localhost:8080", "mcp-front-oauth-with-service-auth",
		testOAuthConfigFromEnv(),
		map[string]any{
			"postgres": testPostgresServer(
				withBearerTokens("svc-bearer-1"),
				withBasicAuth("svc-user", "SVC_PASSWORD"),
			),
		},
	)
	startMCPFront(t, writeTestConfig(t, cfg),
		"JWT_SECRET=test-jwt-secret-32-bytes-exactly!",
		"ENCRYPTION_KEY=test-encryption-key-32-bytes-ok!",
		"GOOGLE_CLIENT_ID=test-client-id-for-oauth",
		"GOOGLE_CLIENT_SECRET=test-client-secret-for-oauth",
		"MCP_FRONT_ENV=development",
		"SVC_PASSWORD=svcpass789",
	)

	waitForMCPFront(t)

	t.Run("bearer service auth bypasses OAuth", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer svc-bearer-1")
		req.Header.Set("Accept", "text/event-stream")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	})

	t.Run("basic service auth bypasses OAuth", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("svc-user:svcpass789")))
		req.Header.Set("Accept", "text/event-stream")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	})

	t.Run("invalid basic credentials still rejected", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("svc-user:wrongpass")))

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("invalid bearer token still rejected", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer not-a-valid-token")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("no auth still rejected", func(t *testing.T) {
		req, err := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		require.NoError(t, err)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("valid OAuth bearer token still works alongside serviceAuths", func(t *testing.T) {
		// Mint a real OAuth access token via the test IDP and confirm
		// ServiceAuth doesn't inadvertently block it. This is the symmetric
		// case to the basic/bearer-service-auth tests above.
		accessToken := getOAuthAccessToken(t, "http://localhost:8080/postgres")

		req, err := http.NewRequest("GET", "http://localhost:8080/postgres/sse", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Accept", "text/event-stream")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))
	})
}
