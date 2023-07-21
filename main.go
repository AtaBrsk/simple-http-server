package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/go-redis/redis"
	"github.com/google/uuid"
)

const (
	errInvalidID = "error invalid id"

	userInfoPath     = "/user-info/"
	createRandomUser = "/create-random-user/"
	leaderBoard      = "/leaderboard/"
	randomMatch      = "/random-match/"

	userIDKey       = "user:id"
	leaderBoardSize = 10
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Password string `json:"password"`
}

type TokenKey struct {
	TokenKey string `json:"tokenkey"`
}

type mac struct {
	UserOneID    string `json:"useroneid"`
	UserOneScore int    `json:"useronescore"`
	UserTwoID    string `json:"usertwoid"`
	UserTwoScore int    `json:"usertwoscore"`
}

type Leaderboard struct {
	UName  string `json:"username"`
	UScore int    `json:"score"`
}

type LeaderboardPage struct {
	Page        int `json:"page"`
	MaxUserPage int `json:"maxuserpage"`
}

type ResponseData struct {
	Status bool        `json:"status"`
	Data   interface{} `json:"data"`
}

type ResponseDataFalse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`
}

type UserRepository struct {
	sync.Mutex
	cache *redis.Client
}

func (repo *UserRepository) userCreate(username, password, name, surname string) (*User, error) {
	repo.Lock()
	defer repo.Unlock()

	id, err := repo.cache.Incr(userIDKey).Result()
	if err != nil {
		return nil, err
	}

	password = hashPassword(password)

	user := &User{
		ID:       int(id),
		Username: username,
		Name:     name,
		Surname:  surname,
		Password: password,
	}

	userData, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}

	token := uuid.New()
	tokenstr := token.String()
	err = repo.cache.Set(("token:" + tokenstr), id, 0).Err()
	if err != nil {
		return nil, err
	}
	err = repo.cache.Set(fmt.Sprintf("tokenid:%d", id), tokenstr, 0).Err()
	if err != nil {
		return nil, err
	}

	err = repo.cache.Set(("username:" + username), id, 0).Err()
	if err != nil {
		return nil, err
	}

	err = repo.cache.Set(fmt.Sprintf("user:%d", id), userData, 0).Err()
	if err != nil {
		return nil, err
	}
	repo.cache.ZAdd("season:leaderboard", redis.Z{Score: 0, Member: id})

	user.Password = ""
	return user, nil
}

func (repo *UserRepository) getUser(username string) int {

	exists, err := repo.cache.Exists(("username:" + username)).Result()
	if err != nil {
		log.Fatalf("Error checking key existence: %v", err)
	}

	if exists == 1 {

		id := repo.cache.Get(("username:" + username))
		Id := id.String()
		id3 := strings.Split(Id, " ")

		idint, err := strconv.Atoi(id3[2])
		if err != nil {
			return 0
		}

		return idint

	}
	return 0

}

func hashPassword(password string) string {
	hash := md5.New()
	hash.Write([]byte(password))
	hashedPassword := hash.Sum(nil)
	return hex.EncodeToString(hashedPassword)
}

func (repo *UserRepository) userInfo(id int) (*User, error) {
	data, err := repo.cache.Get(fmt.Sprintf("user:%d", id)).Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("User not found")
	} else if err != nil {
		return nil, err
	}

	var user User
	err = json.Unmarshal([]byte(data), &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

func (repo *UserRepository) userLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responseDataFalse := ResponseDataFalse{
			Status:  false,
			Message: "Method not allowed",
		}
		responseData, err := json.Marshal(responseDataFalse)
		if err != nil {
			http.Error(w, err.Error(), http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(responseData)
	}

	var user *User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	idint := repo.getUser(user.Username)
	if idint != 0 {

		userPassword := hashPassword(user.Password)

		login, err := repo.userInfo(idint)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		if userPassword == login.Password {

			id := repo.cache.Get(fmt.Sprintf("tokenid:%d", idint))
			Id := id.String()
			id3 := strings.Split(Id, " ")

			responseData := ResponseData{
				Status: true,
				Data:   id3[2],
			}
			jsonToken, err := json.Marshal(responseData)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(jsonToken)
			return
		}
	}

	responseDataFalse := ResponseDataFalse{
		Status:  false,
		Message: "Invalid username or password",
	}
	responseData, err := json.Marshal(responseDataFalse)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	w.Write(responseData)

}

func main() {
	cache := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})

	ping, err := cache.Ping().Result()
	if err != nil {
		fmt.Println("Redis connect fail:", err)
		return
	}
	repo := &UserRepository{
		cache: cache,
	}

	fmt.Println("Redis connect success:", ping)

	http.HandleFunc("/user-login", repo.userLogin)

	http.HandleFunc("/user-update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			responseDataFalse := ResponseDataFalse{
				Status:  false,
				Message: "Method not allowed",
			}
			responseData, err := json.Marshal(responseDataFalse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(responseData)
		}

		header := r.Header

		token := header.Get("Authorization")
		id := repo.cache.Get(("token:" + token))
		Id := id.String()
		id3 := strings.Split(Id, " ")

		idint, err := strconv.Atoi(id3[2])
		if err != nil {
			http.Error(w, errInvalidID, http.StatusBadRequest)
			return
		}

		var UserUpdate *User
		err = json.NewDecoder(r.Body).Decode(&UserUpdate)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if idint > 0 {
			user, err := repo.userInfo(idint)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}

			user.ID = idint

			if len(UserUpdate.Username) != 0 {
				user.Username = UserUpdate.Username
			}

			if len(UserUpdate.Name) != 0 {
				user.Name = UserUpdate.Name
			}

			if len(UserUpdate.Surname) != 0 {
				user.Surname = UserUpdate.Surname
			}

			if len(UserUpdate.Password) != 0 {
				user.Password = hashPassword(UserUpdate.Password)
			}

			userData, err := json.Marshal(user)
			if err != nil {
				return
			}
			err = repo.cache.Set(fmt.Sprintf("user:%d", user.ID), userData, 0).Err()
			if err != nil {
				return
			}
			responseData := ResponseDataFalse{
				Status:  true,
				Message: "Complate",
			}
			jsondata, err := json.Marshal(responseData)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			w.WriteHeader(http.StatusOK)
			w.Write(jsondata)
			return
		}

		responseData := ResponseDataFalse{
			Status:  false,
			Message: "token not found",
		}
		jsondata, err := json.Marshal(responseData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write(jsondata)

	})

	http.HandleFunc(createRandomUser, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			responseDataFalse := ResponseDataFalse{
				Status:  false,
				Message: "Method not allowed",
			}
			responseData, err := json.Marshal(responseDataFalse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(responseData)
		}
		idStr := strings.TrimPrefix(r.URL.Path, createRandomUser)
		idint, err := strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, errInvalidID, http.StatusBadRequest)
			return
		}

		i := 0

		for i < idint {
			id, err := repo.cache.Incr(userIDKey).Result()
			if err != nil {
				return
			}

			user := &User{
				ID:       int(id),
				Username: fmt.Sprintf("player_%d", id),
				Name:     "",
				Surname:  "",
				Password: hashPassword("admin"),
			}
			userData, err := json.Marshal(user)
			if err != nil {
				return
			}

			err = repo.cache.Set(fmt.Sprintf("user:%d", id), userData, 0).Err()
			if err != nil {
				return
			}

			err = repo.cache.Set(("username:" + user.Username), id, 0).Err()
			if err != nil {
				return
			}

			repo.cache.ZAdd("season:leaderboard", redis.Z{Score: 0, Member: id})

			token := uuid.New()

			tokenstr := token.String()
			err = repo.cache.Set(("token:" + tokenstr), id, 0).Err()
			if err != nil {
				return
			}
			err = repo.cache.Set(fmt.Sprintf("tokenid:%d", id), tokenstr, 0).Err()
			if err != nil {
				return
			}

			i++

		}
		responseData := ResponseDataFalse{
			Status:  true,
			Message: "Complate",
		}
		jsondata, err := json.Marshal(responseData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(jsondata)

	})

	http.HandleFunc(randomMatch, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			responseDataFalse := ResponseDataFalse{
				Status:  false,
				Message: "Method not allowed",
			}
			responseData, err := json.Marshal(responseDataFalse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(responseData)
		}
		idStr := strings.TrimPrefix(r.URL.Path, randomMatch)
		matchid, err := strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, errInvalidID, http.StatusBadRequest)
			return
		}
		uid, err := repo.cache.Get(userIDKey).Result()
		if err != nil {
			return
		}
		maxuser, err := strconv.Atoi(uid)
		if err != nil {
			http.Error(w, errInvalidID, http.StatusBadRequest)
			return
		}

		matchdrawn := 0
		userone := 0
		usertwo := 0
		useronescore := 0
		usertwoscore := 0
		match := 1
		for match <= matchid {

			log.Println(match)

			userone = rand.Intn(maxuser)%maxuser + 1
			usertwo = rand.Intn(maxuser)%maxuser + 1

			log.Println("match: ", userone, " - ", usertwo)

			if userone != usertwo {

				useronescore = rand.Intn(10)
				usertwoscore = rand.Intn(10)

				log.Println("score: ", useronescore, " - ", usertwoscore)

				if useronescore == usertwoscore {
					log.Println("draw")
					matchdrawn++
				}
				if useronescore > usertwoscore {

					cache.ZIncrBy("season:leaderboard", 3, fmt.Sprint(userone))
				} else {

					cache.ZIncrBy("season:leaderboard", 3, fmt.Sprint(usertwo))
				}
				match++

			}

		}
		log.Println(matchdrawn)
		responseData := ResponseDataFalse{
			Status:  true,
			Message: "Complate",
		}
		jsondata, err := json.Marshal(responseData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(jsondata)

	})

	http.HandleFunc("/leaderboard", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			responseDataFalse := ResponseDataFalse{
				Status:  false,
				Message: "Method not allowed",
			}
			responseData, err := json.Marshal(responseDataFalse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(responseData)
		}
		var Lpage LeaderboardPage
		err := json.NewDecoder(r.Body).Decode(&Lpage)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		start := (Lpage.Page * Lpage.MaxUserPage) - Lpage.MaxUserPage + 1
		finish := (Lpage.Page * Lpage.MaxUserPage)

		lBoard := make([]*Leaderboard, 0, Lpage.MaxUserPage)

		result, err := cache.ZRevRangeWithScores("season:leaderboard", int64(start), int64(finish)).Result()
		if err != nil {
			log.Fatal(err)
		}
		for _, player := range result {

			id, err := strconv.Atoi(player.Member.(string))
			if err != nil {
				http.Error(w, errInvalidID, http.StatusBadRequest)
				return
			}
			u, err := repo.userInfo(id)
			if err != nil {
				http.Error(w, errInvalidID, http.StatusBadRequest)
				return
			}

			lb := &Leaderboard{UName: u.Username, UScore: int(player.Score)}
			lBoard = append(lBoard, lb)
		}

		responseData := ResponseData{
			Status: true,
			Data:   lBoard,
		}
		jsondata, err := json.Marshal(responseData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(jsondata)

	})

	http.HandleFunc("/leaderboard-top10", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			responseDataFalse := ResponseDataFalse{
				Status:  false,
				Message: "Method not allowed",
			}
			responseData, err := json.Marshal(responseDataFalse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(responseData)
		}
		result, err := cache.ZRevRangeWithScores("season:leaderboard", 0, leaderBoardSize).Result()
		if err != nil {
			log.Fatal(err)
		}
		lBoard := make([]*Leaderboard, 0, leaderBoardSize)

		for _, player := range result {

			id, err := strconv.Atoi(player.Member.(string))
			if err != nil {
				http.Error(w, errInvalidID, http.StatusBadRequest)
				return
			}
			u, err := repo.userInfo(id)
			if err != nil {
				http.Error(w, errInvalidID, http.StatusBadRequest)
				return
			}

			lb := &Leaderboard{UName: u.Username, UScore: int(player.Score)}
			lBoard = append(lBoard, lb)
		}

		responseData := ResponseData{
			Status: true,
			Data:   lBoard,
		}
		jsondata, err := json.Marshal(responseData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(jsondata)

	})

	http.HandleFunc("/match", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			responseDataFalse := ResponseDataFalse{
				Status:  false,
				Message: "Method not allowed",
			}
			responseData, err := json.Marshal(responseDataFalse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(responseData)
		}
		var mach mac
		err := json.NewDecoder(r.Body).Decode(&mach)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if mach.UserOneScore == mach.UserTwoScore {
			log.Println("draw")
			return
		}

		if mach.UserOneScore > mach.UserTwoScore {

			cache.ZIncrBy("season:leaderboard", 3, mach.UserOneID)
		} else {
			cache.ZIncrBy("season:leaderboard", 3, mach.UserTwoID)
		}

		responseData := ResponseDataFalse{
			Status:  true,
			Message: "Complate",
		}
		jsondata, err := json.Marshal(responseData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write(jsondata)

	})

	http.HandleFunc("/user-create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			responseDataFalse := ResponseDataFalse{
				Status:  false,
				Message: "Method not allowed",
			}
			responseData, err := json.Marshal(responseDataFalse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(responseData)
		}
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		userid := repo.getUser(user.Username)
		if userid > 0 {
			responseDataFalse := ResponseDataFalse{
				Status:  false,
				Message: "username already exists",
			}
			responseData, err := json.Marshal(responseDataFalse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(responseData)
			return
		}

		createdUser, err := repo.userCreate(user.Username, user.Password, user.Name, user.Surname)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		responseData := ResponseData{
			Status: true,
			Data:   createdUser,
		}

		jsonResponse, err := json.Marshal(responseData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write(jsonResponse)

	})

	http.HandleFunc(userInfoPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			responseDataFalse := ResponseDataFalse{
				Status:  false,
				Message: "Method not allowed",
			}
			responseData, err := json.Marshal(responseDataFalse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			w.Write(responseData)
		}
		idStr := strings.TrimPrefix(r.URL.Path, userInfoPath)
		id, err := strconv.Atoi(idStr)
		if err != nil {
			http.Error(w, errInvalidID, http.StatusBadRequest)
			return
		}

		user, err := repo.userInfo(id)
		user.Password = ""
		if err != nil {
			responseDataFalse := ResponseDataFalse{
				Status:  false,
				Message: "User not found",
			}
			responseData, err := json.Marshal(responseDataFalse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			w.Write(responseData)
			return
		}
		respondeData := ResponseData{
			Status: true,
			Data:   user,
		}

		jsonResponse, err := json.Marshal(respondeData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(jsonResponse)

	})

	http.ListenAndServe(":8090", nil)
}

//docker exec -it myredis sh
