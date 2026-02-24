package models

import (
	"time"

	"gorm.io/gorm"
)

type StringArray []string

type User struct {
	ID                     uint           `gorm:"primaryKey;autoIncrement" json:"id"`
	Username               string         `gorm:"size:255;uniqueIndex;not null" json:"username"`
	Roles                  StringArray    `gorm:"type:json;default:'[]'" json:"roles"`
	Password               string         `gorm:"size:255;not null" json:"-"`
	Name                   string         `gorm:"size:255;not null" json:"name"`
	Surname                string         `gorm:"size:255;not null" json:"surname"`
	Email                  string         `gorm:"size:255;uniqueIndex;not null" json:"email"`
	Abbreviation           *string        `gorm:"size:50" json:"abbreviation,omitempty"`
	Position               *string        `gorm:"size:255" json:"position,omitempty"`
	ShowOnEmployeeList     bool           `gorm:"default:true" json:"show_on_employee_list"`
	ArchivedAt             *time.Time     `json:"archived_at,omitempty"`
	Phone                  *string        `gorm:"size:50" json:"phone,omitempty"`
	CanManageWorkScheduled bool           `gorm:"default:false" json:"can_manage_work_scheduled"`
	CanManageWorkToSee     bool           `gorm:"default:false" json:"can_manage_work_to_see"`
	CalendarToken          *string        `gorm:"size:255" json:"calendar_token,omitempty"`
	CalendarTokenCreatedAt *time.Time     `json:"calendar_token_created_at,omitempty"`
	AccessLogs             []AccessLog    `gorm:"foreignKey:UserID" json:"access_logs,omitempty"`
	Configurations         []Configuration `gorm:"foreignKey:UserID" json:"configurations,omitempty"`
	PasswordResetTokens    []PasswordResetToken `gorm:"foreignKey:UserID" json:"password_reset_tokens,omitempty"`
}

func (User) TableName() string {
	return "users"
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&AccessLog{},
		&Configuration{},
		&PasswordResetToken{},
	)
}
