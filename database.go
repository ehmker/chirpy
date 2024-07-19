package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	Path 	string
	mu 		*sync.RWMutex
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users map[int]User `json:"users"`
}

type Chirp struct {
	Id int `json:"id"`
	Body string `json:"body"`
}
type User struct {
	Id int `json:"id"`
	Email string `json:"email"`
	Password string `json:"password,omitempty"`
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
func (db *DB) CreateChirp(body string) (Chirp, error) {
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
			Users: 	make(map[int]User),}
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

