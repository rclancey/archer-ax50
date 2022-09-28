package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/rclancey/archer-ax50"
)

func main() {
	client, err := ax50.NewClient(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	err = client.Login(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	clients, err := client.GetClientList()
	if err != nil {
		log.Fatal(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(clients)
}
