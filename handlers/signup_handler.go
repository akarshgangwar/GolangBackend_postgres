package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/akarshgangwar/GolangBackend_postgres/models"
	"gorm.io/gorm"
)

func SignupHandler(c *gin.Context, db *gorm.DB) {
	var user models.Emp
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	err := CreateUser(&user, db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User created successfully"})
}

func CreateUser(user *models.Emp, db *gorm.DB) error {
	result := db.Create(&user)
	if result.Error != nil {
		return result.Error
	}
	return nil
}
