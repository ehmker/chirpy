package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
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
		respondWithError(w, 500, "Something went wrong")
		return
	} 

	user, err := cfg.db.UserLogin(params.Email, params.Password)
	if err != nil {
		respondWithError(w, 401, err.Error())
	}
	respondWithJSON(w, 200, user)


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
