package auth

import (
	"github.com/hdev-sec/xt-ath/auth/models"

	"github.com/gin-gonic/gin"
)

// RegisterAuthRoutes mounts all authentication routes on the given router group.
// Public routes: /signup, /login, /refresh
// Protected routes (require Bearer token): /logout, /deactivate, /validate, /access-log/:id
func RegisterAuthRoutes(rg *gin.RouterGroup, cfg Config) error {
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return err
	}

	if cfg.AutoMigrate {
		if err := models.AutoMigrate(cfg.DB); err != nil {
			return err
		}
	}

	repo := NewRepository(cfg.DB)
	handler := &AuthHandler{Config: cfg, Repo: repo}

	// Public routes
	rg.POST("/signup", handler.Signup)
	rg.POST("/login", handler.Login)
	rg.POST("/refresh", handler.RefreshToken)

	// Protected routes
	protected := rg.Group("", AuthMiddleware(cfg.JWTSecret))
	protected.POST("/logout", handler.Logout)
	protected.POST("/deactivate", handler.DeactivateAccount)
	protected.GET("/validate", handler.ValidateTokenHandler)
	protected.PUT("/access-log/:id", handler.UpdateAccessLog)

	return nil
}
