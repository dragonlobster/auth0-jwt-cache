JWT Validator for Auth0 (https://auth0.com/) that caches public JWKS (since there is a limit on calls to public JWKS URL)

Example securing a `GraphQL` server using `chi-router`:

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/dragonlobster/auth0-jwt-cache/auth"
	"github.com/dragonlobster/example-repo/example"
	"github.com/dragonlobster/example-db-connection/common"
	"github.com/go-chi/chi/v5"
)

const defaultPort = "8080"

func main() {

	pool, err := common.ConnectToDB()

	if err == nil {
		log.Printf("Connected to DB")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	config := generated.Config{Resolvers: &graph.Resolver{
		ExampleRepo: example.ExampleRepo{Pool: pool},
	}}

	srv := handler.NewDefaultServer(generated.NewExecutableSchema(config))
	playground := playground.Handler("GraphQL playground", "/query")

	cert := auth.CachedCert{
		JWKSUrl: PUBLIC_JWKS_URL,
		Aud:     AUDIENCE,
		Iss:     ISSUER,
	}

	auth0_validator, _ := cert.ValidateToken()

	router := chi.NewRouter()

	router.Handle("/", auth0_validator.Handler(playground))
	router.Handle("/query", auth0_validator.Handler(srv))

	log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

```

The above code secures `/` and `/query` endpoint with jwt middleware that validates a JWT (signed with private key) using auth0 public JWKS url, its audience, and issuer - sending a request to these endpoints will require a valid JWT to be in Authorization header as bearer: `Authorization: Bearer abcd123456`
