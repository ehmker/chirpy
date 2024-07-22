package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type apiConfig struct {
	fileserverHits 	int
	nextID 			int
	db 				DB
	jwtSecret		string
}

//Organizational =>
//Attaching all handlers to the multiplexer
func attachHandlers (mux *http.ServeMux, config *apiConfig) *http.ServeMux {
	fileServer := http.FileServer(http.Dir("./app"))

	mux.Handle("/app/*", config.middlewareMetricsInc(http.StripPrefix("/app", fileServer)))
	mux.HandleFunc("GET /api/healthz", healthzHandler)
	mux.HandleFunc("GET /api/metrics", config.fileserverCountHandler)
	mux.HandleFunc("/api/reset", config.resetHandler)
	mux.HandleFunc("GET /admin/metrics", config.adminMetricsHandler)
	mux.HandleFunc("POST /api/chirps", config.postChirpHandler)
	mux.HandleFunc("GET /api/chirps", config.getChirpsHandler)
	mux.HandleFunc("GET /api/chirps/{chirpid}", config.getChirpByIDHandler)
	mux.HandleFunc("POST /api/users", config.postUserHandler)
	mux.HandleFunc("POST /api/login", config.postLoginHandler)
	mux.HandleFunc("PUT /api/users", config.putUserHandler)
	mux.HandleFunc("POST /api/refresh", config.postRefreshHandler)
	mux.HandleFunc("POST /api/revoke", config.postRevokeHandler)

	return mux
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc( func (w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits += 1
		next.ServeHTTP(w, r)
	})
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (cfg *apiConfig) fileserverCountHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf("Hits: %d", cfg.fileserverHits)))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) { 
	cfg.fileserverHits = 0
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Reset hits"))
}

func (cfg *apiConfig) adminMetricsHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(fmt.Sprintf(`<html>
<body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
</body>

</html>`, cfg.fileserverHits)))
}

func (cfg *apiConfig) postChirpHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)

	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	} 

	if len(params.Body) > 140 {
		respondWithError(w, 400, "Chirp is too long")
		return
	}
	params.Body = cleanMessage(params.Body)
	chirp, err  := cfg.db.CreateChirp(params.Body)
	if err != nil {
		log.Println("error creating chirp: ", err)
		respondWithError(w, 500, "Something went wrong")
		return
	}

	respondWithJSON(w, 201, chirp)
}

func (cfg *apiConfig) postUserHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email string `json:"email"`
		Password string  `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)

	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	} 

	user, err := cfg.db.CreateUser(params.Email, params.Password)
	if err != nil {
		log.Println("error creating user: ", err)
		respondWithError(w, 500, err.Error())
		return
	}

	respondWithJSON(w, 201, user)

}

func (cfg *apiConfig)  postLoginHandler(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email 				string 	`json:"email"`
		Password 			string  `json:"password"`
		ExpiresInSeconds 	int 	`json:"expires_in_seconds"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)

	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	} 

	user, err := cfg.db.UserLogin(params.Email, params.Password)
	if err != nil {
		respondWithError(w, 401, err.Error())
	}
	
	//auth token
	signedStr, err := cfg.generateAuthToken(user.Id)
	if err != nil{
		log.Println("error signing token string: ", err)
		respondWithError(w, 500, err.Error())
	}
	user.AuthToken = signedStr
	
	//refresh token
	user.RefreshToken, err = cfg.db.generateRefreshToken(user.Id)
	if err != nil {
		log.Println("error generating refresh token: ", err.Error())
		respondWithError(w, 500, err.Error())
	}
	respondWithJSON(w, 200, user)


}

func (cfg *apiConfig) postRefreshHandler(w http.ResponseWriter, r *http.Request) {
	rToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	userID, ok := cfg.db.refreshTokenIsOK(rToken)
	if !ok { 
		respondWithError(w, 401, "invalid token")
	}
	
	newAuth, err := cfg.generateAuthToken(userID)
	if err != nil {
		respondWithError(w, 500, err.Error())
	}
	respondWithJSON(w, 200, struct{
		Token string `json:"token"`
	}{Token: newAuth})
}

func (cfg *apiConfig) postRevokeHandler (w http.ResponseWriter, r *http.Request) {
	rToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	cfg.db.removeRefreshToken(rToken)
	respondWithJSON(w, 204, nil)
}


func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	allChirps, err := cfg.db.GetChirps()
	if err != nil {
		log.Println("error getting chirps: ", err)
		respondWithError(w, 500, "Something went wrong")
		return
	}
	respondWithJSON(w, 200, allChirps)	
}

func (cfg *apiConfig) getChirpByIDHandler(w http.ResponseWriter, r *http.Request) {
	pathParts := strings.Split(r.RequestURI, "/")
	
	if len(pathParts) != 4 {
		log.Println("request longer than expected: ", pathParts)
		return
	}

	chirpID, err := strconv.Atoi(pathParts[3])
	if err != nil {
		log.Printf("problem converting id to in: '%s'\n", pathParts[3])
	}
	chirp, err := cfg.db.GetChirpByID(chirpID)
	if err != nil {
		respondWithError(w, 404, "chirp not found")
		return
	}

	respondWithJSON(w, 200, chirp)
	
}

func (cfg *apiConfig) putUserHandler(w http.ResponseWriter, r *http.Request) {
	//handle header
	authToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims, err := cfg.parseJWTToken(authToken)
	if err != nil {
		log.Println("error parsing token: ", err)
		respondWithError(w, 401, err.Error())
		return
	}

	userId, err := strconv.Atoi(claims.Subject)

	if err != nil {
		log.Println("error converting to integer: ", err)
	}

	//Handle Body
	type parameters struct {
		Email 				string 	`json:"email"`
		Password 			string  `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		respondWithError(w, 500, "Something went wrong")
		return
	} 

	u, err := cfg.db.UpdateUserLogin(userId, params.Email, params.Password)
	if err != nil{
		respondWithError(w, 500, "Something went wrong")
		return
	}
	respondWithJSON(w, 200, u)
	
}

func (cfg *apiConfig) parseJWTToken(tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, 
		&jwt.RegisteredClaims{}, 
		func (token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			// Return the secret key used for signing
			return []byte(cfg.jwtSecret), nil
	})

	if err != nil || !token.Valid {
		return nil, err
	}
	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
        return claims, nil
    } else {
        return nil, fmt.Errorf("invalid token claims")
    }
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	respBody := struct {Error string `json:"error"`}{}

	w.WriteHeader(code)
	respBody.Error = msg
	dat, err := json.Marshal(respBody)
	if err != nil{
		log.Printf("error marshaling: %s", err)
	}
	w.Write(dat)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	respBody, err := json.Marshal(payload) 
	if err != nil{
		log.Printf("error marshaling: %s", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(respBody)
}

func cleanMessage(s string) string {
	msg := strings.Split(s, " ")
	badWords := []string{ "kerfuffle", "sharbert", "fornax" }
	for i, word := range msg {
		for _, bad := range badWords {
			if strings.Contains(strings.ToLower(word), bad) {
				msg[i] = "****"
				break
			}
		}
	}
	return strings.Join(msg, " ")
}
func (cfg *apiConfig) generateAuthToken(userid int) (string, error) {
	curTime := time.Now().UTC()
	claims := jwt.RegisteredClaims{
		Issuer: "chirpy",
		IssuedAt: jwt.NewNumericDate(curTime),
		ExpiresAt: jwt.NewNumericDate(curTime.Add(time.Duration(1)*time.Hour)),
		Subject: strconv.Itoa(userid),
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	

	return jwtToken.SignedString([]byte(cfg.jwtSecret))
}
