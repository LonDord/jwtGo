package initializers

import "github.com/LonDord/jwtGo/models"

func SyncDB() {
	DB.AutoMigrate(&models.User{})
	DB.AutoMigrate(&models.RefreshToken{})
}
