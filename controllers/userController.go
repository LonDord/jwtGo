package controllers

import (
	"encoding/base64"
	"net/http"
	"os"
	"time"

	"github.com/LonDord/jwtGo/initializers"
	"github.com/LonDord/jwtGo/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func Signup(c *gin.Context) {
	// Get the user details from the request
	var body struct {
		Email    string
		Password string
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to hash password"})
		return
	}

	// Create the user
	user := models.User{
		Email:    body.Email,
		Password: string(hash),
	}
	result := initializers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create user"})
		return
	}

	// Respond
	c.JSON(http.StatusOK, gin.H{"message": "success", "userId": user.Id})
}

func GetPair(c *gin.Context) {
	// Get the id from the request
	id := c.Query("id")

	// Request security check
	parsedID, err := uuid.Parse(id)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}

	// Look up requested user
	var user models.User
	initializers.DB.First(&user, "id = ?", parsedID)

	if user.Id == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No user found"})
		return
	}

	// Generate JWT token
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.Id,
		"exp": time.Now().Add(time.Minute * 20).Unix(),
		"ip":  c.ClientIP(),
	})

	jwtTokenString, err := jwtToken.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create token"})
		return
	}

	// Generate refresh token hash
	originalRefreshToken := uuid.New().String()
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(originalRefreshToken), bcrypt.DefaultCost)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to hash refresh token"})
		return
	}

	// Create refresh token

	var refreshToken models.RefreshToken
	result := initializers.DB.First(&refreshToken, "user_id = ?", user.Id)

	if result.Error != nil && result.Error == gorm.ErrRecordNotFound {
		refreshToken = models.RefreshToken{
			UserId:  user.Id,
			Token:   string(hashedToken),
			Expires: time.Now().Add(time.Hour * 24 * 20).Unix(),
		}

		err := initializers.DB.Create(&refreshToken).Error
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create refresh token"})
			return
		}
	} else if result.Error == nil {
		err := initializers.DB.Model(&refreshToken).Where("user_id = ?", user.Id).Updates(map[string]interface{}{
			"Token":   string(hashedToken),
			"Expires": time.Now().Add(time.Hour * 24 * 20).Unix(),
		}).Error

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to update refresh token"})
			return
		}
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create refresh token"})
		return
	}

	// Refresh token to base64
	basedRefreshToken := base64.StdEncoding.EncodeToString([]byte(originalRefreshToken))

	// Respond
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("RefreshToken", basedRefreshToken, 60*60*24*20, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{"AccessToken": jwtTokenString})
}

func Refresh(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"auth": "yesss"})

}
