use bugtools_events::grpc::proto::coordinator_server::CoordinatorServer;
use bugtools_events::grpc::BugToolsCoordinator;
use tonic::transport::Server;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let addr = "[::1]:50051".parse()?;
    let coordinator = BugToolsCoordinator::default();

    info!("BugTools Rust Coordinator listening on {}", addr);

    Server::builder()
        .add_service(CoordinatorServer::new(coordinator))
        .serve(addr)
        .await?;

    Ok(())
}
