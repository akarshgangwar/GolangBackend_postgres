package main
import (
	"fmt"
	"net/http"
	"strings"
	"time"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var jwtKey = []byte("AK") 
// User represents a user object
type User struct {
	Email string `json:"email"`
	Password string `json:"password"`
}

// Claims represents the claims in the JWT token
type Claims struct {
	Username string `json:"email"`
	jwt.StandardClaims
}

const (
	host     = "localhost"
	port     = 5432
	user     = "akarsh"
	password = "akarsh"
	dbname   = "testDB"
)

func GenerateToken(u User) string {
	expirationTime := time.Now().Add(15 * time.Minute)
	// Create claims
	claims := &Claims{
		Username: u.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	// Generate token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		
		return ""
	}
	return tokenString
}

func LoginHandler(c *gin.Context, db *gorm.DB) {
	var user Emp
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	var dbUser Emp
	db = db.Debug()
	fmt.Print(db)
	if err := db.Where("email = ?", user.Email).First(&dbUser).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials here"})
		return
	}
	if dbUser.Password != user.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}
	tokenUser := User{
		Email:    user.Email,
		Password: user.Password,
	}
	generatedToken := GenerateToken(tokenUser)
	if generatedToken != "" {
		c.JSON(http.StatusOK, gin.H{"token": generatedToken})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
}

func ProtectedHandler(c *gin.Context) {
	
	authHeader  := c.GetHeader("Authorization")
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	// fmt.Println(tokenString)

	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}

	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	// fmt.Println(token)
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token signature"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
		return
	}

	if !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": " token is invalid"})
		return
	}

	// Access the claims
	claims, ok := token.Claims.(*Claims)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token claims"})
		return
	}

	// Perform your protected operations here
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Welcome, %s!", claims.Username)})
}

func CreateUser(user *Emp, db *gorm.DB) error {

	result := db.Create(&user)
	if result.Error != nil {
		return result.Error
	}
	fmt.Print("user created")
	return nil
}

func SignupHandler(c *gin.Context, db *gorm.DB) {
	fmt.Print("hit")
	var user Emp
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	fmt.Println(user)

	result := db.Create(&user)
	
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}
	fmt.Print("user created")
	c.JSON(http.StatusOK, gin.H{"message": "User created successfully"})
}

func CreateServer(){
	db, err := ConnectDB()
	if err != nil {
		panic(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		panic(err)
	}
	defer sqlDB.Close()
	err = db.AutoMigrate(&Emp{})
	if err != nil {
		panic(err)
	}
	router := gin.Default()
	// router.Use(AuthMiddleware())
	
	router.POST("/login", func(c *gin.Context) {
        LoginHandler(c, db) 
    })
	router.GET("/protected", ProtectedHandler)
	router.GET("/testing",AuthMiddleware(),testingRoute)
	router.POST("/signup", func(c *gin.Context) {
		SignupHandler(c ,db)
	})
	router.Run("localhost:8180")
}

func testingRoute(c *gin.Context){
	c.JSON(http.StatusOK, gin.H{"message": "accessed testing route"})
}

func ConnectDB() (*gorm.DB, error) {
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable TimeZone=Asia/Shanghai",
		host, user, password, dbname, port)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("Established a successful connection!")

	return db, nil
}
type Emp struct {
    gorm.Model
    Name    string
    Email   string
    Age     int
    Address string
	Password string
}

func GetUsers(db *gorm.DB) ([]Emp, error) {
	var users []Emp
	result := db.Find(&users)
	if result.Error != nil {
		return nil, result.Error
	}
	fmt.Println(result)
	return users, nil
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			c.Abort()
			return
		}

		// Parse and validate the token
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token signature"})
				c.Abort()
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token is invalid"})
			c.Abort()
			return
		}

		// Set the token claims for further processing in other handlers
		if claims, ok := token.Claims.(*Claims); ok {
			c.Set("claims", claims)
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token claims"})
			c.Abort()
			return
		}

		// Continue with the next handler
		c.Next()
	}
}
func main(){
	CreateServer()
}
