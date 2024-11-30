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

	// Get the jwt token

	accessToken := c.GetHeader("Authorization")
	if accessToken == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "No access token"})
		return
	}

	//Validate

	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, "Token is invalid")
		return
	}

	var ip string
	if claims, ok := token.Claims.(jwt.MapClaims); ok {

		ip = claims["ip"].(string)
		// Check if the token is expired
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, "Token is expired")
			return
		}

		// Find the user

		var user models.User
		initializers.DB.First(&user, "id = ?", claims["sub"].(string))

		if user.Id == uuid.Nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, "User not found")
			return
		}

		c.Set("user", user)

	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, "Token is invalid")
		return
	}

	// Get the cookie
	refreshTokenString, err := c.Cookie("RefreshToken")

	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// get the refreshToken
	userFromContext, _ := c.Get("user")
	user := userFromContext.(models.User)

	var refreshToken models.RefreshToken
	initializers.DB.First(&refreshToken, "user_id = ?", user.Id)

	// decode from base64
	decodedRefreshToken, _ := base64.StdEncoding.DecodeString(refreshTokenString)
	originalRefreshToken := string(decodedRefreshToken)

	// compare DB and cookie refresh token
	err = bcrypt.CompareHashAndPassword([]byte(refreshToken.Token), []byte(originalRefreshToken))

	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, "Refresh token is invalid")
		return
	}

	// compare ips and send email

	if ip != c.ClientIP() {
		to := []string{user.Email} // Получатель
		subject := "В Ваш аккаунт вошли с другого адреса."
		body := fmt.Sprintf("В Ваш аккаунт вошли с подозрительного адреса (%s). Если это были не Вы - обратитесь в службу поддержки.", c.ClientIP())

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

	c.Next()
}
