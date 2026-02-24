package auth

import (
	"errors"
	"time"

	"git.extark.com/go-modules/gin-auth.git/auth/models"
	"github.com/golang-jwt/jwt/v5"
)

const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

// Claims represents the JWT claims used by this module.
type Claims struct {
	jwt.RegisteredClaims
	UserID    uint            `json:"user_id"`
	Username  string          `json:"username"`
	Roles     models.StringArray `json:"roles"`
	TokenType string          `json:"token_type"`
}

// GenerateAccessToken creates a signed access JWT for the given user.
func GenerateAccessToken(user models.User, secret string, ttl time.Duration) (string, error) {
	return generateToken(user, secret, ttl, TokenTypeAccess)
}

// GenerateRefreshToken creates a signed refresh JWT for the given user.
func GenerateRefreshToken(user models.User, secret string, ttl time.Duration) (string, error) {
	return generateToken(user, secret, ttl, TokenTypeRefresh)
}

func generateToken(user models.User, secret string, ttl time.Duration, tokenType string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		UserID:    user.ID,
		Username:  user.Username,
		Roles:     user.Roles,
		TokenType: tokenType,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateToken parses and validates a JWT string, returning the claims.
func ValidateToken(tokenString, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}
	return claims, nil
}

// RefreshTokens validates a refresh token and returns a new access/refresh token pair.
func RefreshTokens(refreshToken, secret string, accessTTL, refreshTTL time.Duration) (string, string, error) {
	claims, err := ValidateToken(refreshToken, secret)
	if err != nil {
		return "", "", err
	}
	if claims.TokenType != TokenTypeRefresh {
		return "", "", errors.New("token is not a refresh token")
	}

	user := models.User{
		ID:       claims.UserID,
		Username: claims.Username,
		Roles:    claims.Roles,
	}

	newAccess, err := GenerateAccessToken(user, secret, accessTTL)
	if err != nil {
		return "", "", err
	}
	newRefresh, err := GenerateRefreshToken(user, secret, refreshTTL)
	if err != nil {
		return "", "", err
	}
	return newAccess, newRefresh, nil
}
