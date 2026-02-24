package models

import "time"

type AccessLog struct {
	ID           uint       `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID       uint       `gorm:"not null;index" json:"user_id"`
	User         User       `gorm:"foreignKey:UserID" json:"user,omitempty"`
	CreatedByID  *uint      `gorm:"index" json:"created_by_id,omitempty"`
	CreatedBy    *User      `gorm:"foreignKey:CreatedByID" json:"created_by,omitempty"`
	ModifiedByID *uint      `gorm:"index" json:"modified_by_id,omitempty"`
	ModifiedBy   *User      `gorm:"foreignKey:ModifiedByID" json:"modified_by,omitempty"`
	EntryTime    time.Time  `gorm:"not null" json:"entry_time"`
	ExitTime     *time.Time `json:"exit_time,omitempty"`
	Reason       *string    `gorm:"type:text" json:"reason,omitempty"`
	IsAllDay     bool       `gorm:"default:false" json:"is_all_day"`
	CreatedAt    time.Time  `gorm:"autoCreateTime" json:"created_at"`
	ModifiedAt   time.Time  `gorm:"autoUpdateTime" json:"modified_at"`
}

func (AccessLog) TableName() string {
	return "access_logs"
}
