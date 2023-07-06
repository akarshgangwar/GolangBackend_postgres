package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/akarshgangwar/GolangBackend_postgres/models"
	"gorm.io/gorm"
	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("AK")

func GenerateToken(u models.User) (string, error) {
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &models.Claims{
		Username: u.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func LoginHandler(c *gin.Context, db *gorm.DB) {
	var user models.Emp
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	var dbUser models.Emp
	db = db.Debug()
	if err := db.Where("email = ?", user.Email).First(&dbUser).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	if dbUser.Password != user.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	tokenUser := models.User{
		Email:    user.Email,
		Password: user.Password,
	}
	generatedToken, err := GenerateToken(tokenUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": generatedToken})
}

func ProtectedHandler(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	tokenString := getTokenFromHeader(authHeader)

	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}

	token, err := parseToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	if !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is invalid"})
		return
	}

	claims, ok := token.Claims.(*models.Claims)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token claims"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Welcome, %s!", claims.Username)})
}

func getTokenFromHeader(authHeader string) string {
	const bearerPrefix = "Bearer "
	if authHeader == "" {
		return ""
	}
	if len(authHeader) > len(bearerPrefix) && authHeader[:len(bearerPrefix)] == bearerPrefix {
		return authHeader[len(bearerPrefix):]
	}
	return ""
}

func parseToken(tokenString string) (*jwt.Token, error) {
	return jwt.ParseWithClaims(tokenString, &models.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
}

func TestingHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Accessed testing route"})
}
