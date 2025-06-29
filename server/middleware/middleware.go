package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/justinas/alice"
	"github.com/saurabhdhingra/go-csrf/db"
	"github.com/saurabhdhingra/go-csrf/server/middleware/myJwt"
	"github.com/saurabhdhingra/go-csrf/templates"
)

func NewHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/static/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		http.ServeFile(w, r, "templates/style.css")
	})
	mux.Handle("/", alice.New(recoverHandler, authHandler).ThenFunc(logicHandler))
	return mux
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
			setCsrfCookie(&w, csrfSecret)
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
		data := struct {
			CsrfToken string
			Message   string
		}{
			CsrfToken: csrfSecret,
			Message:   "Hello! You are now authenticated with CSRF protection.",
		}
		templates.RenderTemplate(w, "restricted", data)
	case "/login":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "login", nil)
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
			setCsrfCookie(&w, csrfSecret)
			http.Redirect(w, r, "/restricted", 302)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/register":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "register", nil)
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
			setCsrfCookie(&w, csrfSecret)
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

	// Clear CSRF cookie
	csrfCookie := http.Cookie{
		Name:    "CSRFToken",
		Value:   "",
		Expires: time.Now().Add(-1000 * time.Hour),
		Path:    "/",
	}
	http.SetCookie(*w, &csrfCookie)

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

func setCsrfCookie(w *http.ResponseWriter, csrfToken string) {
	csrfCookie := http.Cookie{
		Name:     "CSRFToken",
		Value:    csrfToken,
		HttpOnly: false, // Allow JavaScript access for AJAX requests
		Path:     "/",
	}
	http.SetCookie(*w, &csrfCookie)
}

func grabCsrfFromReq(r *http.Request) string {
	// First check form data
	csrfFromForm := r.FormValue("X-CSRF-Token")
	if csrfFromForm != "" {
		return csrfFromForm
	}

	// Then check headers
	csrfFromHeader := r.Header.Get("X-CSRF-Token")
	if csrfFromHeader != "" {
		return csrfFromHeader
	}

	// Finally check cookies
	csrfCookie, err := r.Cookie("CSRFToken")
	if err == nil && csrfCookie.Value != "" {
		return csrfCookie.Value
	}

	return ""
}
