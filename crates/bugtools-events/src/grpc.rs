pub mod proto {
    tonic::include_proto!("bugtools.v1");
}

use proto::coordinator_server::Coordinator;
use proto::{RequestJob, RequestObservation};
use tonic::{Request, Response, Status};
use tokio_stream::wrappers::ReceiverStream;
use tokio::sync::mpsc;
use tracing::info;

#[derive(Debug, Default)]
pub struct BugToolsCoordinator;

#[tonic::async_trait]
impl Coordinator for BugToolsCoordinator {
    type ExecuteHttpJobStream = ReceiverStream<Result<RequestObservation, Status>>;

    async fn execute_http_job(
        &self,
        request: Request<RequestJob>,
    ) -> Result<Response<Self::ExecuteHttpJobStream>, Status> {
        let job = request.into_inner();
        info!("Received RequestJob: {:?}", job.job_id);

        let (tx, rx) = mpsc::channel(4);

        // This is a stub implementation for the contract. 
        // In reality, this would hook into the Go engines or handle simulated responses.
        // The Rust side shouldn't actually *implement* ExecuteHttpJob logic itself in production; 
        // Rust *calls* this on Go, OR Rust implements a service that Go connects to 
        // to receive jobs. For a Coordinator, Rust usually streams jobs TO Go, and Go streams observations back.
        
        // Let's model this as Rust receiving an observation stream for now to satisfy the tonic interface.
        tokio::spawn(async move {
            let obs = RequestObservation {
                job_id: job.job_id.clone(),
                observation_id: "obs-123".to_string(),
                status: 200,
                headers: std::collections::HashMap::new(),
                body: b"OK".to_vec(),
                elapsed_ms: 120,
                timestamp_unix_ms: 1690000000,
            };
            tx.send(Ok(obs)).await.unwrap();
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
