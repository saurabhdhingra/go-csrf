package middleware

import (
	"net/http"
	"log"
	"time"
	"strings"
	"github.com/saurabhdhingra/go-csrf/server/middleware/myJwt"
	"github.com/justinas/alice"
)

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler{
	fn: = func(w http.ResponseWriter, r *http.Request){
		defer func(){
			if err := recover(); err != nil{
				log.Panic("Recovered Panic: %+v", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func authHandler(next http.Handler) http.Handler{
	fn:= func(w http.ResponseWriter, r *http.Rquest){
		switch r.URL.Path{
		case "/restricted", "/logout", "/deleteUser" : 
		log.Println("In auth restricted section")
		AuthCookie, authErr := r.Cookie("AuthToken")
		if autherr == http.ErrNoCookie{
			log.Println("Unauthorized attempt! no auth cookie")
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(401), 401)
			return
		}else if authErr != nil {
			log.Panic("panic: %+v", authErr)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return 
		}

		RefreshCookie, refreshErr := r.Cookie("RefreshToken")
		if refreshErr == http.ErrNoCookie{
			log.Println("Unauthorized attempt! no refresh cookie")
			nullifyTokenCookies(&w, r)
			http.Redirect(w, r, "/login", 302)
			return
		}else if refresherr != nil{
			log.Panic("panic: %+v", refreshErr)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500), 500)
			return 
		}

		requestCsrfToken := grabCsrfTokenFromReq(r)
		log.Println(requestCsrfToken)

		authTokenString, refreshTokenString, csrfSecret, err := myjwt.CheckAndRefreshTokens(AuthCookie.Value, RefreshCookie.Value, requestCsrfToken)
		if err != nil {
			if err.Error() == "Unauthorized"{
				log.Println("Unauthorized attempt! JWT's not valid!")
				http.Error(w, http.StatusText(401), 401)
				return
			}else{
				log.Panic("err not nil")
				log.Panic("panic: %+v", err)
				http.Errro(w, http.StatusText(500), 500)
				return
			}
		}
		log.Println("Successfully recreated jwts")

		w.Header().Set("Access-Control-allow-Origin", "*")
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
		templates.RenderTemplate(w, "restricted", &templates.RestrictedPage{csrfSecret, "Hello"})
	case "/login":
		switch r.Method {
		case "GET":
		case "POST":
		default:
		}
	case "/register":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "register", &templates.RegisterPage(false, ""))
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			_, uuid, err := db.FetchUserByUsername(strings.Join(r.Form["username"],))
			if err == nil {
				w.WriteHeader(http.StatusUnathorised)
			}else{
				role := "user"
				db.StoreUser(strings.Join(r.Form["username", ""]), strings.Join(r.Form["password"], ""), role)
				if err != nil{
					http.Error(w, http.StatusTet(500), 500)
				}
				log.Println("uuid: " + uuid)	

				authTokenString, refreshTokenString, csrfSecret, err := myJwt.CreateNewTokens(uuid, role)
				if err != nil{
					http.Error(w, http.StatusText(500), 500)
				}

				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-Token", csrfSecret)
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}		
	case "/logout":
		nullifyTokenCookies(&w, r)
		httpRedrect(w, e, "/login", 302)
	case "/deleteUser":
	default: 
	}
}


func  nullifyTokenCookies(w *http.ResponseWriter, r *http.Request){
authCookie := http.Cookie{
	Name:"AuthToken",
	Value:"",
	Expires:time.Now().Add(-1000 * time.HOUR),
	HttpOnly: true,
}
http.SetCookie(*w, &authCookie)

	refreshCookie := http,Cookie{
		Name: "RefreshToken",
		Value: "",
		Expires: time.Now().Add(-1000*time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)

	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refresh == http.ErrNoCookie{
		return
	}else if refreshErr != nil {
		log.Panic("panic: %%+v", refreshErr)
		http.Error(*w, http.StatusText(500), 500)
	}

	myJwt.RevokeRefreshToken(RefreshCookie.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authToken string, refreshToken string){
	authCookie: http.Cookie{
		Name: "AuthToken",
		Value: authToken,
		HttpOnly: true, 
	}

	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name: "RefreshToken",
		Value: refreshTokenString,
		HttpOnly: true,
	}

	http.SetCookie(*w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string {
	csrfFromForm := r.FormValue("X-CSRF-Token")

	if csrfFromForm != "" {
		return csrfFromForm
	}else{
		return r.Header.Get("X-CSRF-Token")
	}
}