package auth

import (
	"net/http"
	"time"

	"git.extark.com/go-modules/gin-auth.git/auth/models"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// AuthHandler holds the config, repository, and exposes HTTP handler methods.
type AuthHandler struct {
	Config Config
	Repo   *Repository
}

type signupRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Name     string `json:"name" binding:"required"`
	Surname  string `json:"surname" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
}

type loginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type updateAccessLogRequest struct {
	ExitTime *time.Time `json:"exit_time"`
	Reason   *string    `json:"reason"`
}

// Signup creates a new user, hashes the password, and returns tokens.
func (h *AuthHandler) Signup(c *gin.Context) {
	var req signupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	user := models.User{
		Username: req.Username,
		Password: string(hash),
		Name:     req.Name,
		Surname:  req.Surname,
		Email:    req.Email,
		Roles:    models.StringArray{},
	}

	if err := h.Repo.CreateUser(&user); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "username or email already exists"})
		return
	}

	accessToken, err := GenerateAccessToken(user, h.Config.JWTSecret, h.Config.AccessTokenTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate access token"})
		return
	}
	refreshToken, err := GenerateRefreshToken(user, h.Config.JWTSecret, h.Config.RefreshTokenTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"user":          user,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// Login verifies credentials, creates an access log entry, and returns tokens.
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.Repo.FindUserByUsername(req.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if user.ArchivedAt != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "account is deactivated"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	now := time.Now()
	accessLog := models.AccessLog{
		UserID:    user.ID,
		EntryTime: now,
	}
	h.Repo.CreateAccessLog(&accessLog)

	accessToken, err := GenerateAccessToken(*user, h.Config.JWTSecret, h.Config.AccessTokenTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate access token"})
		return
	}
	refreshToken, err := GenerateRefreshToken(*user, h.Config.JWTSecret, h.Config.RefreshTokenTTL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":          user,
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// Logout logs the exit time for the user's most recent access log entry.
func (h *AuthHandler) Logout(c *gin.Context) {
	userID, _ := c.Get("userID")
	now := time.Now()

	if uid, ok := userID.(uint); ok {
		h.Repo.CloseLatestAccessLog(uid, now)
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

// DeactivateAccount sets archived_at on the authenticated user's account.
func (h *AuthHandler) DeactivateAccount(c *gin.Context) {
	userID, _ := c.Get("userID")
	now := time.Now()

	uid, ok := userID.(uint)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid user context"})
		return
	}

	rows, err := h.Repo.DeactivateUser(uid, now)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to deactivate account"})
		return
	}
	if rows == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found or already deactivated"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "account deactivated"})
}

// ValidateTokenHandler checks the Authorization header and returns user info.
func (h *AuthHandler) ValidateTokenHandler(c *gin.Context) {
	userID, _ := c.Get("userID")
	username, _ := c.Get("username")
	roles, _ := c.Get("roles")

	c.JSON(http.StatusOK, gin.H{
		"user_id":  userID,
		"username": username,
		"roles":    roles,
	})
}

// RefreshToken accepts a refresh token and returns a new token pair.
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	accessToken, refreshToken, err := RefreshTokens(
		req.RefreshToken,
		h.Config.JWTSecret,
		h.Config.AccessTokenTTL,
		h.Config.RefreshTokenTTL,
	)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

// UpdateAccessLog updates an existing access log entry (exit_time, reason).
func (h *AuthHandler) UpdateAccessLog(c *gin.Context) {
	id := c.Param("id")
	userID, _ := c.Get("userID")

	var req updateAccessLogRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log, err := h.Repo.FindAccessLogByID(id)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "access log not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch access log"})
		return
	}

	updates := map[string]interface{}{}
	if req.ExitTime != nil {
		updates["exit_time"] = req.ExitTime
	}
	if req.Reason != nil {
		updates["reason"] = req.Reason
	}
	if uid, ok := userID.(uint); ok {
		updates["modified_by_id"] = uid
	}

	if len(updates) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no fields to update"})
		return
	}

	if err := h.Repo.UpdateAccessLog(log, updates); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update access log"})
		return
	}

	h.Repo.ReloadAccessLog(log)
	c.JSON(http.StatusOK, log)
}
