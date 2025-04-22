package middleware

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/smtp"
	"os"
	"time"

	"github.com/LonDord/jwtGo/initializers"
	"github.com/LonDord/jwtGo/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func RefreshAuth(c *gin.Context) {
	// Проверяем Access токен
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}

	token, err := jwt.Parse(authHeader, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid access token"})
		return
	}

	// Извлекаем claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}

	// Проверяем expiration
	if float64(time.Now().Unix()) > claims["exp"].(float64) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
		return
	}

	// Получаем пользователя
	var user models.User
	userId, err := uuid.Parse(claims["sub"].(string))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
		return
	}

	if err := initializers.DB.First(&user, "id = ?", userId).Error; err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	// Проверяем Refresh токен
	refreshTokenString, err := c.Cookie("RefreshToken")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Refresh token missing"})
		return
	}

	decodedRefresh, err := base64.StdEncoding.DecodeString(refreshTokenString)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token format"})
		return
	}

	// Получаем jti из Access токена
	accessId, err := uuid.Parse(claims["jti"].(string))
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid access token ID"})
		return
	}

	// Ищем Refresh токен в БД
	var dbRefreshToken models.RefreshToken
	result := initializers.DB.Where(
		"user_id = ? AND access_id = ?",
		user.Id,
		accessId,
	).First(&dbRefreshToken)

	if result.Error != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Refresh token not found for this access token"})
		return
	}

	// Сравниваем токены
	if err := bcrypt.CompareHashAndPassword(
		[]byte(dbRefreshToken.Token),
		decodedRefresh,
	); err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Refresh token mismatch"})
		return
	}

	// Проверяем IP
	currentIP := c.ClientIP()
	if claims["ip"] != currentIP || dbRefreshToken.IP != currentIP {
		sendIPChangedNotification(user.Email, currentIP)
	}

	// Удаляем использованный Refresh токен
	initializers.DB.Delete(&dbRefreshToken)

	// Сохраняем пользователя в контекст
	c.Set("user", user)
	c.Next()
}

func sendIPChangedNotification(email, newIP string) {
	to := []string{email}
	subject := "В Ваш аккаунт вошли с другого адреса."
	body := fmt.Sprintf("В Ваш аккаунт вошли с подозрительного адреса (%s). Если это были не Вы - обратитесь в службу поддержки.", newIP)

	message := []byte(fmt.Sprintf("Subject: %s\n\n%s", subject, body))

	err := smtp.SendMail(
		os.Getenv("SMTP_ADDR"),
		initializers.SmtpAuth,
		os.Getenv("FROM_EMAIL"),
		to,
		message,
	)

	if err != nil {
		fmt.Printf("Send mail error %v", err)
		return
	}
}
