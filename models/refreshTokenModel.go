package models

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	Id        uuid.UUID `gorm:"type:uuid;primary_key"`
	UserId    uuid.UUID `gorm:"type:uuid;not null"`
	Token     string    `gorm:"type:varchar(255);not null;unique"`
	AccessId  uuid.UUID `gorm:"type:uuid;not null;index"`
	IP        string    `gorm:"type:varchar(45);not null"`
	Expires   int64     `gorm:"not null"`
	CreatedAt time.Time
}
