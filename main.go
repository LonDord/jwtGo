package main

import (
	"github.com/LonDord/jwtGo/controllers"
	"github.com/LonDord/jwtGo/initializers"
	"github.com/LonDord/jwtGo/middleware"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVars()
	initializers.ConnectToDB()
	initializers.SyncDB()
}

func main() {
	r := gin.Default()
	r.POST("/signup", controllers.Signup)
	r.GET("/getpair", controllers.GetPair)
	r.POST("/refresh", middleware.RefreshAuth, controllers.Refresh)
	r.Run()
}
