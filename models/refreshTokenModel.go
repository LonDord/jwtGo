package models

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	UserId    uuid.UUID `gorm:"type:uuid;"`
	Token     string    `gorm:"type:varchar(63);not null;unique"`
	Expires   int64     `gorm:"type:bigint;not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}
