package main
import (
	"github.com/gin-gonic/gin"
	"github.com/akarshgangwar/GolangBackend_postgres/handlers"
	"github.com/akarshgangwar/GolangBackend_postgres/middlewares"
	"github.com/akarshgangwar/GolangBackend_postgres/database"
)

func main() {
	db, err := database.ConnectDB()
	if err != nil {
		panic(err)
	}

	router := gin.Default()

	router.POST("/login", func(c *gin.Context) {
		handlers.LoginHandler(c, db)
	})
	router.GET("/protected", handlers.ProtectedHandler)
	router.GET("/testing", middlewares.AuthMiddleware(), handlers.TestingHandler)
	router.POST("/signup", func(c *gin.Context) {
		handlers.SignupHandler(c, db)
	})
	router.GET("/refresh-token", handlers.RefreshTokenHandler)


	router.Run("localhost:8180")
}
