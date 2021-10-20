package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/form3tech-oss/jwt-go"
)

type Response struct {
	Message string `json:"message"`
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type Cert struct {
	Content string
	Expiry  time.Time
}

type CachedCert struct {
	cachedCert *Cert
	certsMutex sync.RWMutex
	JWKSUrl    string
	Aud        string
	Iss        string
}

func (c *CachedCert) ValidateToken() (*jwtmiddleware.JWTMiddleware, error) {
	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			// Verify 'aud' claim
			aud := c.Aud
			checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
			if !checkAud {
				return token, errors.New("invalid audience")
			}
			// Verify 'iss' claim
			iss := c.Iss
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
			if !checkIss {
				return token, errors.New("invalid issuer")
			}

			cert, err := c.getPemCert(token)
			if err != nil {
				return token, errors.New("unable to get token")
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert.Content))
			return result, nil

		},
		SigningMethod: jwt.SigningMethodRS256,
	})

	return jwtMiddleware, nil
}

func (c *CachedCert) getPemCert(token *jwt.Token) (*Cert, error) {

	c.certsMutex.RLock()
	cert := c.cachedCert
	c.certsMutex.RUnlock()

	if cert != nil {
		if time.Now().Before(cert.Expiry) {
			return cert, nil
		}
	}

	c.certsMutex.Lock()
	defer c.certsMutex.Unlock()

	newCert, err := fetchPemCert(token, c.JWKSUrl)

	if err != nil {
		return nil, err
	}

	c.cachedCert = newCert
	return newCert, nil

}

func fetchPemCert(token *jwt.Token, jwksUrl string) (*Cert, error) {
	cert := ""
	resp, fetchError := http.Get(jwksUrl)

	if fetchError != nil {
		return nil, fetchError
	}

	cacheControl := resp.Header.Get("cache-control")
	cacheAge := time.Hour * 10
	if len(cacheControl) > 0 {
		re := regexp.MustCompile("max-age=([0-9]*)")
		match := re.FindAllStringSubmatch(cacheControl, -1)
		if len(match) > 0 {
			if len(match[0]) == 2 {
				maxAge := match[0][1]
				maxAgeInt, err := strconv.ParseInt(maxAge, 10, 64)
				if err != nil {
					return nil, err
				}
				cacheAge = time.Duration(maxAgeInt) * time.Second
			}
		}
	}

	defer resp.Body.Close()

	var jwks = Jwks{}
	decoderError := json.NewDecoder(resp.Body).Decode(&jwks)

	if decoderError != nil {
		return nil, decoderError
	}

	for k, _ := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("unable to find appropriate key")
		return nil, err
	}

	return &Cert{
		Content: cert,
		Expiry:  time.Now().Add(cacheAge),
	}, nil
}
