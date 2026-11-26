package main

import (
	"fmt"
	"log"
	"os"

	vnetwork "github.com/vnetworkx/vnetwork-sdk-go"
)

func main() {
	endpoint := os.Getenv("VNETWORK_ENDPOINT")
	if endpoint == "" {
		endpoint = "http://127.0.0.1:8080"
	}
	networkID := os.Getenv("VNETWORK_NETWORK_ID")
	if networkID == "" {
		networkID = "vector-devnet-1"
	}

	identity, err := vnetwork.GenerateIdentity("go-sdk-participant")
	if err != nil {
		log.Fatal(err)
	}
	if identity.ParticipantKey.PublicKeyHex == identity.NodeKey.PublicKeyHex {
		log.Fatal("participant and node keys must remain distinct")
	}

	client := vnetwork.NewClient(endpoint, identity, networkID)
	info, err := client.Connect()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Connected via Go SDK to %s (height=%d)\n", info.NetworkID, info.Height)

	joinRes, err := client.Join([]string{"NETWORK", "SPACE", "REGION", "WALLET", "TOKEN"})
	if err != nil {
		log.Fatal(err)
	}
	pMap := joinRes["participant"].(map[string]any)
	fmt.Printf("Joined participant: %s\n", pMap["participant_id"])

	var sub vnetwork.ProgramSubmission
	if len(os.Args) > 1 {
		sub, err = client.SubmitVxFile(os.Args[1])
	} else {
		source := `
space create GoSdkSpace {
    name = "Go SDK Space";
    visibility = "public";
}
region create GoSdkRegion in "GoSdkSpace" {
    prefix = "GOS";
    visibility = "public";
    section = 1;
}
wallet create GoWalletA in "GoSdkRegion" {
    name = "Go Wallet A";
}
wallet create GoWalletB in "GoSdkRegion" {
    name = "Go Wallet B";
}
token create GOTOK in "GoWalletA" {
    name = "Go Token";
    symbol = "GOTOK";
    dimensions = 3;
    vector = [20000, 1000, 0];
    max_supply = 20000;
    drain_bps = 100;
    purpose = "Go SDK integration";
    external_monetary_value = "None";
}
transfer "GOTOK" from "GoWalletA" to "GoWalletB" amount 350;
verify proof network;
`
		sub, err = client.SubmitProgram("go_workflow.vx", source, nil)
	}
	if err != nil {
		log.Fatal(err)
	}
	if sub.Status != "COMMITTED" {
		log.Fatalf("expected COMMITTED, got %s", sub.Status)
	}
	fmt.Printf("Committed Go program %s (entities=%d)\n", sub.ProgramID, len(sub.CreatedEntities))

	for _, ent := range sub.CreatedEntities {
		if ent.Kind == "token" {
			rep, err := client.VerifyReconstruction("token", ent.ID)
			if err != nil {
				log.Fatal(err)
			}
			if !rep.Verified {
				log.Fatalf("reconstruction failed for %s", ent.ID)
			}
			fmt.Printf("Verified Go reconstruction for %s: %s\n", ent.ID, rep.ReconstructedHash)
			break
		}
	}
}
