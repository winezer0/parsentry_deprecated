use anyhow::Result;

use parsentry::cli::RootCommand;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    RootCommand::execute().await
}
