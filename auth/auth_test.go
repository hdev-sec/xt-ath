package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hdev-sec/xt-ath/auth"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	gormPg "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// testEnv holds shared state for all E2E tests.
type testEnv struct {
	server *httptest.Server
	db     *gorm.DB
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase("ginauth_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { pgContainer.Terminate(ctx) })

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := gorm.Open(gormPg.Open(connStr), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	r := gin.New()

	authGroup := r.Group("/auth")
	err = auth.RegisterAuthRoutes(authGroup, auth.Config{
		DB:          db,
		JWTSecret:   "test-secret",
		AutoMigrate: true,
	})
	require.NoError(t, err)

	server := httptest.NewServer(r)
	t.Cleanup(func() { server.Close() })

	return &testEnv{server: server, db: db}
}

func postJSON(url string, body interface{}, token string) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return http.DefaultClient.Do(req)
}

func putJSON(url string, body interface{}, token string) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return http.DefaultClient.Do(req)
}

func getWithToken(url, token string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return http.DefaultClient.Do(req)
}

func decodeBody(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)
	resp.Body.Close()
	return body
}

// --- Tests ---

func TestSignupAndLogin(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	// Signup
	resp, err := postJSON(base+"/signup", map[string]string{
		"username": "alice",
		"password": "Secret123!",
		"name":     "Alice",
		"surname":  "Smith",
		"email":    "alice@example.com",
	}, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	body := decodeBody(t, resp)
	assert.NotEmpty(t, body["access_token"])
	assert.NotEmpty(t, body["refresh_token"])

	user := body["user"].(map[string]interface{})
	assert.Equal(t, "alice", user["username"])
	assert.Equal(t, "Alice", user["name"])
	assert.Equal(t, "alice@example.com", user["email"])

	// Login with correct credentials
	resp, err = postJSON(base+"/login", map[string]string{
		"username": "alice",
		"password": "Secret123!",
	}, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body = decodeBody(t, resp)
	assert.NotEmpty(t, body["access_token"])
	assert.NotEmpty(t, body["refresh_token"])
}

func TestLoginWrongPassword(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	// Create user first
	resp, err := postJSON(base+"/signup", map[string]string{
		"username": "bob",
		"password": "Correct123!",
		"name":     "Bob",
		"surname":  "Jones",
		"email":    "bob@example.com",
	}, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	// Login with wrong password
	resp, err = postJSON(base+"/login", map[string]string{
		"username": "bob",
		"password": "WrongPassword!",
	}, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	body := decodeBody(t, resp)
	assert.Equal(t, "invalid credentials", body["error"])
}

func TestSignupDuplicateUsername(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	payload := map[string]string{
		"username": "charlie",
		"password": "Pass123!",
		"name":     "Charlie",
		"surname":  "Brown",
		"email":    "charlie@example.com",
	}

	resp, err := postJSON(base+"/signup", payload, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	resp.Body.Close()

	// Signup again with same username
	resp, err = postJSON(base+"/signup", payload, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)

	body := decodeBody(t, resp)
	assert.Equal(t, "username or email already exists", body["error"])
}

func TestValidateToken(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	// Signup to get a token
	resp, err := postJSON(base+"/signup", map[string]string{
		"username": "diana",
		"password": "Pass123!",
		"name":     "Diana",
		"surname":  "Prince",
		"email":    "diana@example.com",
	}, "")
	require.NoError(t, err)
	body := decodeBody(t, resp)
	accessToken := body["access_token"].(string)

	// Validate
	resp, err = getWithToken(base+"/validate", accessToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body = decodeBody(t, resp)
	assert.Equal(t, "diana", body["username"])
	assert.NotZero(t, body["user_id"])
}

func TestValidateTokenWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	resp, err := getWithToken(base+"/validate", "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	body := decodeBody(t, resp)
	assert.Equal(t, "missing authorization header", body["error"])
}

func TestValidateTokenInvalid(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	resp, err := getWithToken(base+"/validate", "not-a-real-token")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestRefreshToken(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	// Signup
	resp, err := postJSON(base+"/signup", map[string]string{
		"username": "eve",
		"password": "Pass123!",
		"name":     "Eve",
		"surname":  "Taylor",
		"email":    "eve@example.com",
	}, "")
	require.NoError(t, err)
	body := decodeBody(t, resp)
	refreshToken := body["refresh_token"].(string)

	// Refresh
	resp, err = postJSON(base+"/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body = decodeBody(t, resp)
	assert.NotEmpty(t, body["access_token"])
	assert.NotEmpty(t, body["refresh_token"])

	// The new access token should be valid
	newAccessToken := body["access_token"].(string)
	resp, err = getWithToken(base+"/validate", newAccessToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()
}

func TestRefreshWithAccessTokenFails(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	// Signup
	resp, err := postJSON(base+"/signup", map[string]string{
		"username": "frank",
		"password": "Pass123!",
		"name":     "Frank",
		"surname":  "Miller",
		"email":    "frank@example.com",
	}, "")
	require.NoError(t, err)
	body := decodeBody(t, resp)
	accessToken := body["access_token"].(string)

	// Try to refresh using the access token instead of refresh token
	resp, err = postJSON(base+"/refresh", map[string]string{
		"refresh_token": accessToken,
	}, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	resp.Body.Close()
}

func TestLogout(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	// Signup
	resp, err := postJSON(base+"/signup", map[string]string{
		"username": "grace",
		"password": "Pass123!",
		"name":     "Grace",
		"surname":  "Hopper",
		"email":    "grace@example.com",
	}, "")
	require.NoError(t, err)
	signupBody := decodeBody(t, resp)
	accessToken := signupBody["access_token"].(string)

	// Login to create an access log entry
	resp, err = postJSON(base+"/login", map[string]string{
		"username": "grace",
		"password": "Pass123!",
	}, "")
	require.NoError(t, err)
	loginBody := decodeBody(t, resp)
	accessToken = loginBody["access_token"].(string)

	// Logout
	resp, err = postJSON(base+"/logout", nil, accessToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body := decodeBody(t, resp)
	assert.Equal(t, "logged out", body["message"])
}

func TestDeactivateAccount(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	// Signup
	resp, err := postJSON(base+"/signup", map[string]string{
		"username": "hank",
		"password": "Pass123!",
		"name":     "Hank",
		"surname":  "Green",
		"email":    "hank@example.com",
	}, "")
	require.NoError(t, err)
	body := decodeBody(t, resp)
	accessToken := body["access_token"].(string)

	// Deactivate
	resp, err = postJSON(base+"/deactivate", nil, accessToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body = decodeBody(t, resp)
	assert.Equal(t, "account deactivated", body["message"])

	// Try to login after deactivation — should be forbidden
	resp, err = postJSON(base+"/login", map[string]string{
		"username": "hank",
		"password": "Pass123!",
	}, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	body = decodeBody(t, resp)
	assert.Equal(t, "account is deactivated", body["error"])
}

func TestDeactivateAlreadyDeactivated(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	// Signup
	resp, err := postJSON(base+"/signup", map[string]string{
		"username": "iris",
		"password": "Pass123!",
		"name":     "Iris",
		"surname":  "West",
		"email":    "iris@example.com",
	}, "")
	require.NoError(t, err)
	body := decodeBody(t, resp)
	accessToken := body["access_token"].(string)

	// Deactivate
	resp, err = postJSON(base+"/deactivate", nil, accessToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Deactivate again (token still valid since JWT is stateless)
	resp, err = postJSON(base+"/deactivate", nil, accessToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestUpdateAccessLog(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	// Signup
	resp, err := postJSON(base+"/signup", map[string]string{
		"username": "jane",
		"password": "Pass123!",
		"name":     "Jane",
		"surname":  "Doe",
		"email":    "jane@example.com",
	}, "")
	require.NoError(t, err)
	resp.Body.Close()

	// Login to create an access log entry
	resp, err = postJSON(base+"/login", map[string]string{
		"username": "jane",
		"password": "Pass123!",
	}, "")
	require.NoError(t, err)
	body := decodeBody(t, resp)
	accessToken := body["access_token"].(string)

	// Find the access log ID from the database
	var logID uint
	env.db.Raw("SELECT id FROM access_logs ORDER BY id DESC LIMIT 1").Scan(&logID)
	require.NotZero(t, logID)

	// Update the access log
	exitTime := time.Now().UTC().Truncate(time.Second)
	reason := "end of shift"
	resp, err = putJSON(
		fmt.Sprintf("%s/access-log/%d", base, logID),
		map[string]interface{}{
			"exit_time": exitTime.Format(time.RFC3339),
			"reason":    reason,
		},
		accessToken,
	)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body = decodeBody(t, resp)
	assert.Equal(t, reason, body["reason"])
	assert.NotNil(t, body["exit_time"])
}

func TestUpdateAccessLogNotFound(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	// Signup to get a token
	resp, err := postJSON(base+"/signup", map[string]string{
		"username": "kate",
		"password": "Pass123!",
		"name":     "Kate",
		"surname":  "Bishop",
		"email":    "kate@example.com",
	}, "")
	require.NoError(t, err)
	body := decodeBody(t, resp)
	accessToken := body["access_token"].(string)

	// Update non-existent access log
	resp, err = putJSON(
		base+"/access-log/99999",
		map[string]interface{}{"reason": "test"},
		accessToken,
	)
	require.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	resp.Body.Close()
}

func TestProtectedRoutesRequireAuth(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	routes := []struct {
		method string
		path   string
	}{
		{"POST", "/logout"},
		{"POST", "/deactivate"},
		{"GET", "/validate"},
		{"PUT", "/access-log/1"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			var resp *http.Response
			var err error
			url := base + route.path

			switch route.method {
			case "GET":
				resp, err = getWithToken(url, "")
			case "POST":
				resp, err = postJSON(url, nil, "")
			case "PUT":
				resp, err = putJSON(url, map[string]interface{}{"reason": "test"}, "")
			}

			require.NoError(t, err)
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			resp.Body.Close()
		})
	}
}

func TestFullFlow(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	// 1. Signup
	resp, err := postJSON(base+"/signup", map[string]string{
		"username": "fullflow",
		"password": "Flow123!",
		"name":     "Full",
		"surname":  "Flow",
		"email":    "fullflow@example.com",
	}, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	body := decodeBody(t, resp)
	refreshToken := body["refresh_token"].(string)

	// 2. Login
	resp, err = postJSON(base+"/login", map[string]string{
		"username": "fullflow",
		"password": "Flow123!",
	}, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body = decodeBody(t, resp)
	accessToken := body["access_token"].(string)
	refreshToken = body["refresh_token"].(string)

	// 3. Validate
	resp, err = getWithToken(base+"/validate", accessToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body = decodeBody(t, resp)
	assert.Equal(t, "fullflow", body["username"])

	// 4. Refresh
	resp, err = postJSON(base+"/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body = decodeBody(t, resp)
	accessToken = body["access_token"].(string)

	// 5. Validate again with new token
	resp, err = getWithToken(base+"/validate", accessToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body = decodeBody(t, resp)
	assert.Equal(t, "fullflow", body["username"])

	// 6. Update access log
	var logID uint
	env.db.Raw("SELECT id FROM access_logs WHERE user_id = (SELECT id FROM users WHERE username = 'fullflow') ORDER BY id DESC LIMIT 1").Scan(&logID)
	require.NotZero(t, logID)

	reason := "lunch break"
	resp, err = putJSON(
		fmt.Sprintf("%s/access-log/%d", base, logID),
		map[string]interface{}{"reason": reason},
		accessToken,
	)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body = decodeBody(t, resp)
	assert.Equal(t, reason, body["reason"])

	// 7. Logout
	resp, err = postJSON(base+"/logout", nil, accessToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// 8. Deactivate
	resp, err = postJSON(base+"/deactivate", nil, accessToken)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// 9. Login after deactivation should fail
	resp, err = postJSON(base+"/login", map[string]string{
		"username": "fullflow",
		"password": "Flow123!",
	}, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	resp.Body.Close()
}

func TestSignupValidation(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	cases := []struct {
		name    string
		payload map[string]string
	}{
		{"missing username", map[string]string{"password": "p", "name": "n", "surname": "s", "email": "a@b.com"}},
		{"missing password", map[string]string{"username": "u", "name": "n", "surname": "s", "email": "a@b.com"}},
		{"missing name", map[string]string{"username": "u", "password": "p", "surname": "s", "email": "a@b.com"}},
		{"missing email", map[string]string{"username": "u", "password": "p", "name": "n", "surname": "s"}},
		{"invalid email", map[string]string{"username": "u", "password": "p", "name": "n", "surname": "s", "email": "not-email"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := postJSON(base+"/signup", tc.payload, "")
			require.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			resp.Body.Close()
		})
	}
}

func TestLoginNonExistentUser(t *testing.T) {
	env := setupTestEnv(t)
	base := env.server.URL + "/auth"

	resp, err := postJSON(base+"/login", map[string]string{
		"username": "nobody",
		"password": "whatever",
	}, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	body := decodeBody(t, resp)
	assert.Equal(t, "invalid credentials", body["error"])
}
