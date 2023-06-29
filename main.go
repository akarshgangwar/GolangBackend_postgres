package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
)

func main(){
	fmt.Println("running")
}

func CreateServer(){
	
	router := gin.Default()
	router.Run("localhost:8080")
	router.POST("/login", LoginHandler)
	router.GET("/protected", ProtectedHandler)

}
