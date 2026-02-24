package models

type Configuration struct {
	ID      uint   `gorm:"primaryKey;autoIncrement" json:"id"`
	Keyname string `gorm:"size:255;not null" json:"keyname"`
	Value   string `gorm:"type:text;not null" json:"value"`
	UserID  *uint  `gorm:"index" json:"user_id,omitempty"`
	User    *User  `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

func (Configuration) TableName() string {
	return "configurations"
}
