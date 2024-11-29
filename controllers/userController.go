package controllers

import (
	"net/http"
	"os"
	"time"

	"github.com/LonDord/jwtGo/initializers"
	"github.com/LonDord/jwtGo/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
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
	c.JSON(http.StatusOK, gin.H{"message": "success"})
}

func GetPair(c *gin.Context) {
	// Get the id from the request
	var body struct {
		Id uuid.UUID
	}

	if c.Bind(&body) != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read body"})
		return
	}

	// Look up requested user
	var user models.User
	initializers.DB.First(&user, "id = ?", body.Id)

	if user.Id == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No user found"})
		return
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": user.Id,
		"exp": time.Now().Add(time.Minute * 20).Unix(),
		"ip":  c.ClientIP(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to create token"})
		return
	}

	// Send it back
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}
