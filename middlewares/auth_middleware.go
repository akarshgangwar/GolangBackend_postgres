package middlewares

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/akarshgangwar/GolangBackend_postgres/models"
	"github.com/dgrijalva/jwt-go"
)

var jwtKey = []byte("AK")

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		tokenString := getTokenFromHeader(authHeader)

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			c.Abort()
			return
		}

		token, err := parseToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			c.Abort()
			return
		}

		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is invalid"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(*models.Claims); ok {
			c.Set("claims", claims)
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Next()
	}
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
