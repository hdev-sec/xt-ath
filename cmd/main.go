package main

import (
	"fmt"
	"log"
	"os"

	"extark/gin-auth/auth"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_USER", "postgres"),
		getEnv("DB_PASSWORD", "postgres"),
		getEnv("DB_NAME", "ginauth"),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	r := gin.Default()

	authGroup := r.Group("/auth")
	if err := auth.RegisterAuthRoutes(authGroup, auth.Config{
		DB:          db,
		JWTSecret:   getEnv("JWT_SECRET", "dev-secret-change-me"),
		AutoMigrate: true,
	}); err != nil {
		log.Fatalf("failed to register auth routes: %v", err)
	}

	port := getEnv("PORT", "8080")
	log.Printf("starting server on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
