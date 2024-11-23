package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

var db *sql.DB
var jwtKey []byte

type Admin struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// My struct That will return the user
type User struct {
	Username string `json:"username"`
	Email string `json:"email"`
}

// This will initialize the db and store the local connection pool to the global one "db"
func initDB() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file:", err)
	}

	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	connectionString := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	//fmt.Println("CONNECTED TO DB") // SEE IF CONNECTED TO DB

	/*
	   The problem with init fxn is that Its not creating a table here. Thats WHy when I do POST request in Postman its giving error
	*/
	
	db, err = sql.Open("mysql", connectionString)
	if err != nil {
		log.Fatal("Error opening database:", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatal("Error pinging database:", err)
	}

	// HERE I CREATED A TABLE AS ITS NOT EXISTING IN DATABASE ITSELF !!!
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS admins (id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, username TEXT NOT NULL, password TEXT NOT NULL, email TEXT NOT NULL)")

	fmt.Println("Database connection successful")
}

// This fxn will generate SECRET KEY and will store in global variable for the JWT signature stamp
func generateJWTKey() {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal("Error generating JWT key:", err)
	}
	jwtKey = key
}

// This add new Admins
func addAdminHandler(w http.ResponseWriter, r *http.Request) {
	var admin Admin
	err := json.NewDecoder(r.Body).Decode(&admin)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(admin.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error hashing password: %v", err), http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO admins (username, password, email) VALUES (?, ?, ?)", 
		admin.Username, string(hashedPassword), admin.Email)
	
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating admin: %v", err), http.StatusInternalServerError)
		return
	}

	// Send email with login credentials
	err = sendEmail(admin.Email, admin.Username, admin.Password)
	if err != nil {
		log.Printf("Error sending email: %v", err)
		// Continue even if email sending fails
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Admin created successfully"})
}


// Its for login funtion
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	fmt.Println("Attempting to login with username:", creds.Username)

	var storedPassword string
	err = db.QueryRow("SELECT password FROM admins WHERE username = ?", creds.Username).Scan(&storedPassword)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusUnauthorized)
		} else {
			http.Error(w, "Database error", http.StatusInternalServerError)
		}
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(creds.Password))
	
	if err != nil {
		http.Error(w, "Incorrect password", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(1 * time.Minute) // Here I added 1 minute expiry to the JWT token
	
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	/*
	   This fxn is just returing the JWT.
	   But this should save the cookie at the frontend side.
	*/

	// Setting JWT as cookie
	http.SetCookie(w, &http.Cookie{
		Name: "jwt",
		Value: tokenString,
		Expires: expirationTime,
		HttpOnly: true,
		Path: "/", // I am setting it to be valid for all paths
	})

	// Now I will return the cookie ans JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString,
		"message": "Successfully Logged in",
	})
}

// AUTHORIZATION FXN THAT WILL AUTHORIZE THE USER TO ACCESS THE PAGE IF HE/SHE HAS ISSUED THE JWT
func UserShow(w http.ResponseWriter, r *http.Request) {
	// First I wil get the cookie
	cookie, err := r.Cookie("jwt")

	if err != nil {
		if err == http.ErrNoCookie {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"message": "unauthenticated",
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Error reading cookie",
		})
		return
	}

	// Now It will parse the token
	claims := &Claims{}
	
	token, err := jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	// check for the expiration here
	if err != nil {
		if err.Error() == "token is expired" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"message": "Token has expired",
			})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Invalid authentication token",
		})
		return
	}

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Invalid token",
		})
		return
	}

	// If everything works fine, I will then Search the database
	var user User // SO that password will not come to postman
	err = db.QueryRow("SELECT username, email FROM admins WHERE username = ?", claims.Username).Scan(&user.Username, &user.Email)

	if err != nil {
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"message": "User not found",
			})
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Database error",
		})
		return
	}

	// Set content type header and just return the user
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(user)
}

// The Logout Feature
func Logout(w http.ResponseWriter, r *http.Request) {
    // Create an expired cookie to overwrite the existing one
    expiredCookie := http.Cookie{
        Name:     "jwt",
        Value:    "",                                // Empty value
        Path:     "/",                               // Must match the path I used during login
        Expires:  time.Now().Add(-24 * time.Hour),   // Setting expiry to one day before  
        MaxAge:   -1,                                // Immediately expire the cookie
        HttpOnly: true,                              
    }

    // Set the expired cookie
    http.SetCookie(w, &expiredCookie)

    // Send success response
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Successfully logged out",
    })
}


func sendEmail(to, username, password string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", to)
	m.SetHeader("To", to)
	m.SetHeader("Subject", "Your CourseConnect Admin Account")
	m.SetBody("text/html", fmt.Sprintf(`
		<h1>Welcome to CourseConnect!</h1>
		<p>Your admin account has been created.</p>
		<p><strong>Username:</strong> %s<br>
		<strong>Password:</strong> %s</p>
		<p>Please log in and change your password immediately.</p>
	`, username, password))

	d := gomail.NewDialer("smtp.gmail.com", 587, to, password)

	return d.DialAndSend(m)
}

func main() {
	initDB()
	generateJWTKey()

	router := mux.NewRouter()

	router.HandleFunc("/admin", addAdminHandler).Methods("POST", "OPTIONS")
	router.HandleFunc("/login", loginHandler).Methods("POST", "OPTIONS")

	// My Handlers
	router.HandleFunc("/user", UserShow).Methods("GET")
	router.HandleFunc("/logout", Logout).Methods("POST")

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"}, // Add your frontend URL
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		Debug:            true, // Enable CORS debugging
	})

	handler := c.Handler(router)

	// Add logging middleware
	loggingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request: %s %s", r.Method, r.URL.Path)
		handler.ServeHTTP(w, r)
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server running on port %s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, loggingHandler))
}
