package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	Path 	string
	mu 		*sync.RWMutex
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users map[int]User `json:"users"`
	RefreshTokens map[string]RefreshToken `json:"refresh_tokens"`
}

type Chirp struct {
	Id int `json:"id"`
	Body string `json:"body"`
	AuthorId int `json:"author_id"`
}
type User struct {
	Id int `json:"id"`
	Email string `json:"email,omitempty"`
	Password string `json:"password,omitempty"`
	AuthToken string `json:"token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}
type RefreshToken struct {
	Id int `json:"id"`
	Token string `json:"token_string"`
	ExpiresAt time.Time `json:"expires_at"`
}



// NewDB creates a new database connection
// and creates the database file if it doesn't exist
func NewDB(path string) (*DB, error) {
	db := DB{
		Path: path,
		mu: &sync.RWMutex{},
	}
	err := db.ensureDB()
	
	return &db, err
}
// CreateChirp creates a new chirp and saves it to disk
func (db *DB) CreateChirp(body string, authorID int) (Chirp, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	database, err := db.loadDB()
	if err != nil {
		log.Printf("error in CreateChirp loading database: %v\n", err)
		return Chirp{}, err
	}
	i := len(database.Chirps) + 1
	newChirp := Chirp{
		Id: i,
		Body: body,
		AuthorId: authorID,

	}

	database.Chirps[i] = newChirp
	err = db.writeDB(database)
	if err != nil {
		log.Printf("error in CreateChirp writing database: %v\n", err)
		return Chirp{}, err
	}

	return newChirp, nil
}

// CreateUser creates a new user and saves it to disk
// Returns resulting user less the password
func (db *DB) CreateUser(email, password string) (User, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	//load db from disk
	database, err := db.loadDB()
	if err != nil {
		log.Printf("error in CreateUser loading database: %v\n", err)
		return User{}, err
	} 
	
	if _, found := database.userEmailExists(email); found {
		return User{}, errors.New("email already in use")
	}
		
	i := len(database.Users) + 1
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil{
		log.Println("error hashing password: ", err)
	}

	database.Users[i] = User{
		Id: i,
		Email: email,
		Password: string(hashedPassword),
	}

	err = db.writeDB(database)
	if err != nil {
		log.Printf("error in CreateUser writing database: %v\n", err)
		return User{}, err
	}

	return User{
		Id: i,
		Email: email,
	}, nil

}

// Attempts to "login" user by checking if email/password match 

func (db *DB) UserLogin(email, password string) (User, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	database, err := db.loadDB()
	if err != nil {
		log.Printf("error in GetChirpByID loading database: %v\n", err)
		return User{}, err
	}
	user, found := database.userEmailExists(email)
	if !found{
		log.Println("user email not found")
		return User{}, errors.New("email not found")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil{
		log.Println("incorrect password")
		return User{}, errors.New("incorrect password")
	}
	
	return User{
		Id: user.Id,
		Email: user.Email,
		}, nil

}

func (db *DB) UpdateUserLogin(id int, email, password string) (User, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	database, err := db.loadDB()
	if err != nil {
		log.Printf("error in GetChirpByID loading database: %v\n", err)
		return User{}, err
	}

	u, exists := database.Users[id]
	if !exists{
		return User{}, errors.New("unable to update login.  user not found")
	}
	
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil{
		log.Println("error hashing password: ", err)
	}

	u.Password = string(hashedPassword)
	u.Email = email
	
	database.Users[id] = u

	err = db.writeDB(database)
	if err != nil {
		log.Printf("error in writing database")
	}

	return User{Id: id,
	Email: email,}, nil
}

// GetChirps returns all chirps in the database
func (db *DB) GetChirps() ([]Chirp, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	chirps := []Chirp{}

	database, err := db.loadDB()
	if err != nil {
		log.Printf("error in GetChirps loading database: %v\n", err)
		return []Chirp{}, err
	}

	for _, chirp := range database.Chirps {
		chirps = append(chirps, chirp)
	}

	return chirps, nil
}

func (db *DB) GetChirpByID(id int) (Chirp, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	database, err := db.loadDB()
	if err != nil {
		log.Printf("error in GetChirpByID loading database: %v\n", err)
		return Chirp{}, err
	}

	c, ok := database.Chirps[id]
	if !ok {
		log.Printf("chirp id not found: %v\n", id)
		return Chirp{}, errors.New("chirp not found in database")
	}

	return c, nil


}

// ensureDB creates a new database file if it doesn't exist
func (db *DB) ensureDB() error {
	err := os.Remove(db.Path)
	if err != nil{
		log.Printf("error removing file: %v", err)
		return err
	}
	os.Create(db.Path)	
	return nil
}

// loadDB reads the database file into memory
func (db *DB) loadDB() (DBStructure, error) {
	dbs := DBStructure{}

	db_file, err := os.ReadFile(db.Path)
	if err != nil {
		log.Println("read error")
		return dbs, err
	}
	
	if len(db_file) == 0 {
		log.Println("Database file is empty, initialize new DBStructure")
		dbs = DBStructure{
			Chirps: make(map[int]Chirp),
			Users: 	make(map[int]User),
			RefreshTokens: map[string]RefreshToken{},}
		return dbs, nil
	}

	err = json.Unmarshal(db_file, &dbs)
	if err != nil {
		log.Println("unmarshel error")
		return dbs, err
	}
	
	return dbs, nil

}

// writeDB writes the database file to disk
func (db *DB) writeDB(dbStructure DBStructure) error {
	jsonPayload, err := json.Marshal(dbStructure)
	if err != nil {
		log.Printf("error marshaling: %v\n%v", dbStructure, err)
	}
	err = os.WriteFile(db.Path, jsonPayload, 0666)

	return err
}

func (db *DBStructure) userEmailExists(email string) (User, bool) {
	email = strings.ToLower(email)
	for i, user := range db.Users{
		if strings.ToLower(user.Email) == email {
			return db.Users[i], true
		}
	}
	return User{}, false
}

func (db *DB) generateRefreshToken(id int) (string, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	
	sz := make([]byte, 32)
	_, err := rand.Read(sz)
	if err != nil {
		return "", err
	}
	encodedRfshStr := hex.EncodeToString(sz)

	tkn := RefreshToken{
		Id: id,
		Token: encodedRfshStr,
		ExpiresAt: time.Now().AddDate(0, 0, 60),
	}

	database, err := db.loadDB()
	if err != nil {
		log.Fatal("problem loading database: ", err.Error())
	}
	database.RefreshTokens[encodedRfshStr] = tkn
	err = db.writeDB(database)
	if err != nil {
		log.Fatal("problem writing database: ", err.Error())
	}

	return encodedRfshStr, nil
}

func (db *DB) refreshTokenIsOK(tkn string) (int, bool){
	db.mu.Lock()
	defer db.mu.Unlock()

	database, err := db.loadDB()
	if err != nil {
		log.Fatal("problem loading database: ", err.Error())
	}

	rfshToken, exists := database.RefreshTokens[tkn]
	if !exists {
		return 0, false
	}
	//return the associated user id and if ExpiresAt is After current time
	return rfshToken.Id, rfshToken.ExpiresAt.After(time.Now())
	
}

func (db *DB) removeRefreshToken(tkn string) {
	db.mu.Lock()
	defer db.mu.Unlock()
	database, err := db.loadDB()
	if err != nil {
		log.Fatal("problem loading database: ", err.Error())
	}
	delete(database.RefreshTokens, tkn)
	db.writeDB(database)
}

func (db *DB)  removeChirpByID(chirpId, AuthorId int) (int, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	database, err := db.loadDB()
	if err != nil {
		log.Fatal("problem loading database: ", err.Error())
	}

	targetChirp, ok := database.Chirps[chirpId]
	
	if !ok {
		return 404, errors.New("chirp does not exist")
	}
	if targetChirp.AuthorId != AuthorId {
		return 403, errors.New("error removing chirp. user is not author")
	}
	delete(database.Chirps, chirpId)
	err = db.writeDB(database)
	if err != nil{
		log.Fatal("problem writing database")
	}
	return 204, nil

}
