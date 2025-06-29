package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/justinas/alice"
	"github.com/saurabhdhingra/go-csrf/db"
	"github.com/saurabhdhingra/go-csrf/server/middleware/myJwt"
)

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Recovered Panic: %+v", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func authHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/restricted", "/logout", "/deleteUser":
			log.Println("In auth restricted section")
			AuthCookie, authErr := r.Cookie("AuthToken")
			if authErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! no auth cookie")
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(401), 401)
				return
			} else if authErr != nil {
				log.Printf("panic: %+v", authErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			RefreshCookie, refreshErr := r.Cookie("RefreshToken")
			if refreshErr == http.ErrNoCookie {
				log.Println("Unauthorized attempt! no refresh cookie")
				nullifyTokenCookies(&w, r)
				http.Redirect(w, r, "/login", 302)
				return
			} else if refreshErr != nil {
				log.Printf("panic: %+v", refreshErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			requestCsrfToken := grabCsrfFromReq(r)
			log.Println(requestCsrfToken)

			authTokenString, refreshTokenString, csrfSecret, err := myJwt.CheckAndRefreshTokens(AuthCookie.Value, RefreshCookie.Value, requestCsrfToken)
			if err != nil {
				if err.Error() == "Unauthorized" {
					log.Println("Unauthorized attempt! JWT's not valid!")
					http.Error(w, http.StatusText(401), 401)
					return
				} else {
					log.Printf("err not nil: %+v", err)
					http.Error(w, http.StatusText(500), 500)
					return
				}
			}
			log.Println("Successfully recreated jwts")

			w.Header().Set("Access-Control-Allow-Origin", "*")
			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)
		default:
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":
		csrfSecret := grabCsrfFromReq(r)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"csrf_token": "` + csrfSecret + `", "message": "Hello"}`))
	case "/login":
		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<!DOCTYPE html>
				<html>
				<head><title>Login</title></head>
				<body>
					<h1>Login</h1>
					<form method="POST" action="/login">
						<input type="text" name="username" placeholder="Username" required><br>
						<input type="password" name="password" placeholder="Password" required><br>
						<input type="submit" value="Login">
					</form>
					<a href="/register">Register</a>
				</body>
				</html>
			`))
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			username := strings.Join(r.Form["username"], "")
			password := strings.Join(r.Form["password"], "")

			user, uuid, err := db.LogUserIn(username, password)
			if err != nil {
				http.Error(w, "Invalid credentials", http.StatusUnauthorized)
				return
			}

			authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, user.Role)
			if err != nil {
				http.Error(w, http.StatusText(500), 500)
				return
			}

			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)
			http.Redirect(w, r, "/restricted", 302)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/register":
		switch r.Method {
		case "GET":
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`
				<!DOCTYPE html>
				<html>
				<head><title>Register</title></head>
				<body>
					<h1>Register</h1>
					<form method="POST" action="/register">
						<input type="text" name="username" placeholder="Username" required><br>
						<input type="password" name="password" placeholder="Password" required><br>
						<input type="submit" value="Register">
					</form>
					<a href="/login">Login</a>
				</body>
				</html>
			`))
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			username := strings.Join(r.Form["username"], "")
			password := strings.Join(r.Form["password"], "")

			_, uuid, err := db.FetchUserByUsername(username)
			if err == nil {
				http.Error(w, "User already exists", http.StatusUnauthorized)
				return
			}

			role := "user"
			uuid, err = db.StoreUser(username, password, role)
			if err != nil {
				http.Error(w, http.StatusText(500), 500)
				return
			}
			log.Println("uuid: " + uuid)

			authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, role)
			if err != nil {
				http.Error(w, http.StatusText(500), 500)
				return
			}

			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-Token", csrfSecret)
			http.Redirect(w, r, "/restricted", 302)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/logout":
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/login", 302)
	case "/deleteUser":
		// TODO: Implement user deletion
		w.WriteHeader(http.StatusNotImplemented)
	case "/csrf":
		// Endpoint to get CSRF token
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"csrf_token": "available_after_login"}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)

	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie {
		return
	} else if refreshErr != nil {
		log.Printf("panic: %+v", refreshErr)
		http.Error(*w, http.StatusText(500), 500)
		return
	}

	myJwt.RevokeRefreshToken(RefreshCookie.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authToken string, refreshToken string) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    authToken,
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    refreshToken,
		HttpOnly: true,
	}

	http.SetCookie(*w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string {
	csrfFromForm := r.FormValue("X-CSRF-Token")

	if csrfFromForm != "" {
		return csrfFromForm
	} else {
		return r.Header.Get("X-CSRF-Token")
	}
}
