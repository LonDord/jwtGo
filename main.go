package main

import (
	"os"

	"github.com/LonDord/jwtGo/controllers"
	"github.com/LonDord/jwtGo/initializers"
	"github.com/LonDord/jwtGo/middleware"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVars()
	initializers.ConnectToDB()
	initializers.SyncDB()
	initializers.ConnectToMail()

}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.POST("/signup", controllers.Signup)
	r.GET("/getpair", controllers.GetPair)
	r.POST("/refresh", middleware.RefreshAuth, controllers.Refresh)
	r.Run(":" + port)
}
