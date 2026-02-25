package auth

import (
	"time"

	"github.com/hdev-sec/xt-ath/auth/models"

	"gorm.io/gorm"
)

// Repository handles all database operations for the auth module.
type Repository struct {
	db *gorm.DB
}

// NewRepository creates a new Repository with the given GORM database connection.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{db: db}
}

// CreateUser inserts a new user into the database.
func (r *Repository) CreateUser(user *models.User) error {
	return r.db.Create(user).Error
}

// FindUserByUsername fetches a user by their username.
func (r *Repository) FindUserByUsername(username string) (*models.User, error) {
	var user models.User
	err := r.db.Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// DeactivateUser sets archived_at on a user that is not yet deactivated.
// Returns the number of rows affected.
func (r *Repository) DeactivateUser(userID uint, now time.Time) (int64, error) {
	result := r.db.Model(&models.User{}).
		Where("id = ? AND archived_at IS NULL", userID).
		Update("archived_at", now)
	return result.RowsAffected, result.Error
}

// CreateAccessLog inserts a new access log entry.
func (r *Repository) CreateAccessLog(log *models.AccessLog) error {
	return r.db.Create(log).Error
}

// FindAccessLogByID fetches an access log entry by its ID.
func (r *Repository) FindAccessLogByID(id string) (*models.AccessLog, error) {
	var log models.AccessLog
	err := r.db.Where("id = ?", id).First(&log).Error
	if err != nil {
		return nil, err
	}
	return &log, nil
}

// UpdateAccessLog applies the given updates to an access log entry.
func (r *Repository) UpdateAccessLog(log *models.AccessLog, updates map[string]interface{}) error {
	return r.db.Model(log).Updates(updates).Error
}

// ReloadAccessLog reloads an access log entry from the database by its ID.
func (r *Repository) ReloadAccessLog(log *models.AccessLog) error {
	return r.db.First(log, log.ID).Error
}

// CloseLatestAccessLog sets exit_time on the most recent open access log for a user.
func (r *Repository) CloseLatestAccessLog(userID uint, exitTime time.Time) error {
	return r.db.Model(&models.AccessLog{}).
		Where("user_id = ? AND exit_time IS NULL", userID).
		Order("created_at DESC").
		Limit(1).
		Update("exit_time", exitTime).Error
}
