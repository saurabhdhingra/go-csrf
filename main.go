package main

import(
	"log"
	"github.com/saurabhdhingra/go-csrf/db"
	"github.com/saurabhdhingra/go-csrf/keys"
	"github.com/saurabhdhingra/go-csrf/server/middleware/myJwt"
)

var host = "localhost"
var port = "9000"

func main(){
	db.InitDB()

	jwtErr := myJwt.InitJWT()
	if jwtErr != nil {
		log.Println("Error Initializing the JWT!")
		log.Fatal(jwtErr)
	}


	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("Error starting the server!")
		log.Fatal(serverErr)
	}
}