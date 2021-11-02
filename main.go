package main

import (
	"brendisurfs/go-gin-auth/auth"
	"log"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func init() {
	envLoadErr := godotenv.Load()
	if envLoadErr != nil {
		log.Fatal("could not find env vars, this app wont work.")
	}
}

func main() {
	// init gin
	router := gin.Default()
	// create routers

	// set up cors for LOCAL Dev only
	router.Use(cors.New(
		cors.Config{
			AllowOrigins:     []string{"http://localhost:3000"},
			AllowCredentials: true,
			AllowHeaders:     []string{"Authorization"},
		},
	))
	// use middleware, protect endpoints
	router.GET(
		"/api/private",
		auth.EnsureToken(),
		func(ctx *gin.Context) {
			response := map[string]string{
				"message": "hello from my private protected endpoints",
			}
			ctx.JSON(http.StatusOK, response)
		},
	)

	// run the server, handle the error.
	runServerErr := router.Run(":3000")
	if runServerErr != nil {
		log.Fatalf("error running the server, %v", runServerErr)
	}
}
