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
	// "gorm.io/gorm"
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

	c.Set("user", user)
	GenerateTokenPair(c)
}

func Refresh(c *gin.Context) {
	GenerateTokenPair(c)
}

func GenerateTokenPair(c *gin.Context) {
	user := c.MustGet("user").(models.User)
	clientIP := c.ClientIP()

	// 1. Генерируем уникальный ID для Access токена
	accessId := uuid.New()

	// 2. Создаем JWT (Access токен)
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.Id,
		"exp": time.Now().Add(time.Minute * 20).Unix(),
		"ip":  clientIP,
		"jti": accessId.String(), // Уникальный идентификатор токена
	})

	accessTokenString, err := accessToken.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	// 3. Генерируем Refresh токен
	rawRefreshToken := uuid.New().String()
	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(rawRefreshToken), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash refresh token"})
		return
	}

	// 4. Сохраняем Refresh токен в БД
	refreshToken := models.RefreshToken{
		Id:       uuid.New(),
		UserId:   user.Id,
		Token:    string(hashedRefreshToken),
		AccessId: accessId, // Связываем с Access токеном
		IP:       clientIP,
		Expires:  time.Now().Add(time.Hour * 24 * 20).Unix(),
	}

	if err := initializers.DB.Create(&refreshToken).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save refresh token"})
		return
	}

	// 5. Отправляем токены клиенту
	encodedRefresh := base64.StdEncoding.EncodeToString([]byte(rawRefreshToken))

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("RefreshToken", encodedRefresh, 60*60*24*20, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessTokenString,
		"expires_in":   time.Now().Add(time.Minute * 20).Unix(),
	})
}
