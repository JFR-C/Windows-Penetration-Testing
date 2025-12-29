package main

import (
	"os"
	"NTFSRegDump/filedump"
	"log"
)

func main() {

	if len(os.Args) < 4 {
		log.SetFlags(0) 
		log.Fatalf("Usage: %s system-output-file security-output-file sam-output-file\n", os.Args[0])
	}

	systemDestFile := os.Args[1]
	securityDestFile := os.Args[2]
	samDestFile := os.Args[3]
	
	log.Printf("Listing available volumes...")
	volumePath := filedump.FindSystemVolume()
	if volumePath == "" {
		log.Fatalf("No system volume found.")
	}

	filedump.ExtractSystemFiles(volumePath, map[string]string{"SYSTEM": systemDestFile, "SECURITY": securityDestFile, "SAM": samDestFile})
}
