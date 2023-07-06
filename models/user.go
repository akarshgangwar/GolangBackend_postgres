package models

import (
	"github.com/dgrijalva/jwt-go"
	"gorm.io/gorm"
)

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"email"`
	jwt.StandardClaims
}

type Emp struct {
	gorm.Model
	Name     string
	Email    string
	Age      int
	Address  string
	Password string
}
