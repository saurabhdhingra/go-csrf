package myJwt

import (
	"io/ioutil"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/saurabhdhingra/go-csrf/db"
	"github.com/saurabhdhingra/go-csrf/db/models"
)

const (
	privKeyPath = "keys/app.rsa"
	pubKeyPath  = "keys/app.rsa.pub"
)

var ()

func InitJWT() error {
	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return err
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return err
	}

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return err
	}

	return nil
}

func CreateNewTokens(uuid string, role string) (authTokenString, refreshTokenString, csrfSecret string, err error) {
	csrfSecret, err = models.GenerateCSRFSecret()
	if err != nil {
		return
	}

	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}

	authTokenString, err = createAuthTokenString(uuid, role, csrfSecret)
	if err != nil {
		return
	}

	return

}

func CheckAndRefreshTokens(oldAuthTokenString string, oldCsrfSecret string) (newAuthTokenString, newRefreshTokenString, newCsrfSecret string,err error ) {

	if oldCsrfSecret == ""{
		log.Println("No CSRF token !")
		err = errors.New("Unauthorized")
		return
	}
	authToken, err := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(token *jwt.Token)(interface{}, error){
		return verifykey, nil
	})
	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)
	if !ok{
		return 
	}

	if oldCsrfSecret != authTokenClaims.Csrf{
		log.Println("CSRF token doesn't match jwt!")
		err = errors.new("Unauthorizes")
		return
	}

	if authToken.Valid{
		log.Println("Auth token is valid" )

		newCsrfSecret = authTokenClaims.Csrf

		newRefreshTokenString = updateRefreshTokenExp(oldRefreshTokenString)
		newAuthTokenString = oldAuthTokenString
	}else if ve, ok := err.(*jwt.ValidationError); ok {
		log.Println("Auth token is not valid")
		if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
			log.Println("Auth token is expired")

			newAuthTokenString, newCsrfSecret := updateAuthTokenString(oldRefreshTokenString, oldAuthTokenString)

			if err!= nil {
				return 
			}

			newRefreshTokenString, err = updateRefreshTokenExp(oldRefreshTokenString)

			if err != nil {
				return
			}

			newRefreshTokenString, err =  updateRefreshTokenCsrf(newRefreshTokenString, newCsrfSecret)
			return
		} else {
			log.Println("error in auth token")
			err = errors.New("error in auth token")
			return
		}
	}else {
		log.Println("error in auth token")
		err = errors.New("error in auth token")
	}
}

func createAuthTokenString(uuid string, role string, csrfSecret string) (authTokenString string, err error) {
	authTokenExp := time.Now().Add(models.AuthTokenValidTime).Unix()
	authClaims := models.TokenClaims{
		jwt.StandardClaims{
			Subject:   uuid,
			ExpiresAt: authTokenExp,
		},
		role,
		csrfSecret,
	}

	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)
	authTokenString, err = authJwt.SignedString(signKey)
	return

}

func createRefreshTokenString(uuid string, role string, csrfString string) (refreshTokenString string, err string) {
	refreshTokenExp := time.Now().Add(models.RefreshTokenValidTime).Unix()
	refreshJti, err := db.StoreRefreshToken()

	if err != nil {
		return
	}

	refreshClaims := models.TokenClaims{
		jwt.StandardClaims{
			Id:        refreshJti,
			Subject:   uuid,
			ExpiresAt: refreshTokenExp,
		}, role,
		csrfString,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)
	refreshTokenString, err = refreshJwt.SignedString(signKey)

	return
}

func updateRefreshTokenExp() {

}

func updateAuthTokenString() {

}

func RevokeRefreshToken() error {

}

func updateRefreshTokenCsrf() {

}

func GrabUUID() {

}
