package auth

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

const (
	DefaultAccessTokenTTL  = 15 * time.Minute
	DefaultRefreshTokenTTL = 7 * 24 * time.Hour
)

// Config holds the configuration for the auth module.
type Config struct {
	DB              *gorm.DB
	JWTSecret       string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	AutoMigrate     bool
}

func (c *Config) defaults() {
	if c.AccessTokenTTL == 0 {
		c.AccessTokenTTL = DefaultAccessTokenTTL
	}
	if c.RefreshTokenTTL == 0 {
		c.RefreshTokenTTL = DefaultRefreshTokenTTL
	}
}

func (c *Config) validate() error {
	if c.DB == nil {
		return errors.New("ginauth: DB is required")
	}
	if c.JWTSecret == "" {
		return errors.New("ginauth: JWTSecret is required")
	}
	return nil
}
