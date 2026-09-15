package main

import (
	"context"
	"io"
	"log"
	"time"

	pb "bugtools/http-go/internal/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// Connect to the Rust Coordinator
	serverAddr := "localhost:50051"
	log.Printf("Connecting to Rust Coordinator at %s...", serverAddr)

	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewCoordinatorClient(conn)

	// Create a dummy RequestJob to test the connection and streaming
	req := &pb.RequestJob{
		JobId:    "job-001",
		TargetId: "target-A",
		Method:   "GET",
		Url:      "http://example.com",
	}

	log.Printf("Sending RequestJob: %s", req.JobId)
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.ExecuteHttpJob(ctx, req)
	if err != nil {
		log.Fatalf("ExecuteHttpJob failed: %v", err)
	}

	for {
		obs, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("Failed to receive observation: %v", err)
		}
		
		log.Printf("Received Observation! Job: %s, ObsID: %s, Status: %d, Elapsed: %dms", 
			obs.JobId, obs.ObservationId, obs.Status, obs.ElapsedMs)
	}
	
	log.Println("Stream finished successfully.")
}
