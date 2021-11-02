package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwtgo "github.com/auth0/go-jwt-middleware/validate/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

const signatureAlgo = "RS256"

// CustomClaims - holds our custom params to use with Auth0
type CustomClaims struct {
	Scope string `json:"scope"`
	jwt.StandardClaims
}

var _ jwtgo.CustomClaims = &CustomClaims{}

type (
	jwks struct {
		Keys []jsonWebKeys `json:"keys"`
	}

	jsonWebKeys struct {
		Kty string   `json:"kty"`
		Kid string   `json:"kid"`
		Use string   `json:"use"`
		N   string   `json:"n"`
		E   string   `json:"e"`
		X5c []string `json:"x5c"`
	}
)

func getPEMCert(token *jwt.Token) (string, error) {

	var jwks jwks

	var cert string

	res, requestErr := http.Get("https://" + os.Getenv("AUTH0_DOMAIN") + "/.well-knonw/jwks.json")
	if requestErr != nil {
		return "", requestErr
	}
	// remebered this question: why cant I defer at the end of the function?
	defer res.Body.Close()

	if requestErr = json.NewDecoder(res.Body).Decode(&jwks); requestErr != nil {
		return "", requestErr
	}

	// search through keys
	for _, key := range jwks.Keys {
		if token.Header["kid"] == key.Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + key.X5c[0] + "\n-----END CERTIFICATE-----"
			break
		}

		if cert == "" {
			return cert, errors.New("unable to find appropriate key")
		}
	}
	return cert, nil
}

// ===========================================================================

// Validate - that our API connection works and that we have the right params.
// |
// v
func (c *CustomClaims) Validate(_ context.Context) error {

	expectedAudience := os.Getenv("AUTH0_AUDENCE")
	if c.Audience != expectedAudience {
		return fmt.Errorf("token claims failed: unexpected audience %q", c.Audience)
	}

	expectedIssuer := "https://" + os.Getenv("AUTH0_DOMAIN") + "/"

	// we get this from our CustomClaims struct jwt extensions.
	if c.Issuer != expectedIssuer {
		return fmt.Errorf("token claims failed -> unexpected issuer %q", c.Issuer)
	}
	return nil
}

// HasScope - checks wheter our claims have a specific scope
func (c *CustomClaims) HasScope(expectedScope string) bool {
	result := strings.Split(c.Scope, " ")
	for i := range result {
		if result[i] == expectedScope {
			return true
		}
	}
	return false
}

// ==========================================================================

// EnsureToken - a middleware handler that will check the validity of our JWT>
// |
// v
func EnsureToken() gin.HandlerFunc {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		certificate, err := getPEMCert(token)
		if err != nil {
			return token, err
		}
		return jwt.ParseRSAPrivateKeyFromPEM([]byte(certificate))
	}
	customClaims := func() jwtgo.CustomClaims {
		return &CustomClaims{}
	}

	// NOTE: OK WTF IS GOING ON HERE, FIGURE THIS OUT
	validator, validatorErr := jwtgo.New(
		keyFunc,
		signatureAlgo,
		jwtgo.WithCustomClaims(customClaims),
	)
	if validatorErr != nil {
		log.Fatalf("failed to set up the jwt validator")
	}

	m := jwtmiddleware.New(validator.ValidateToken)

	//
	return func(ctx *gin.Context) {
		var encounteredError = true
		var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			encounteredError = false
			ctx.Request = r
			ctx.Next()
		}
		m.CheckJWT(handler).ServeHTTP(ctx.Writer, ctx.Request)

		// check if the encountered error is still true

		if encounteredError {
			ctx.AbortWithStatusJSON(
				http.StatusUnauthorized,
				gin.H{"message": "failed to validate JWT"},
			)
		}
	}
}
