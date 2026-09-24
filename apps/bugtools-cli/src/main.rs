//! BugTools CLI — parse, initialize, dispatch.
//!
//! All argument definitions live in `cli.rs`; each command's execution lives
//! in `commands/`. This file only wires them together.

mod cli;
mod commands;
mod output;
mod parsing;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

use commands::sqli::SqliOptions;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Target { input } => commands::target::run(&input).await,

        Commands::Discover { input, json } => commands::discover::run(&input, json).await,

        Commands::Resolve { hostname, types } => commands::resolve::run(&hostname, &types).await,

        Commands::Pipeline {
            input,
            out,
            depth,
            max_urls,
            rps,
        } => commands::pipeline::run(&input, out.as_deref(), depth, max_urls, rps).await,

        Commands::Sql { command } => commands::sql::run(command).await,

        Commands::Tech {
            url,
            i_authorize,
            cookies,
            headers,
            bearer,
            json,
            program,
            handle,
        } => {
            commands::tech::run(
                &url,
                i_authorize,
                &cookies,
                &headers,
                bearer.as_deref(),
                json,
                program.as_deref(),
                handle.as_deref(),
            )
            .await
        }

        Commands::Xss {
            url,
            i_authorize,
            param,
            method,
            data,
            cookies,
            headers,
            bearer,
            json,
            program,
            handle,
        } => {
            let opts = commands::xss::XssOptions {
                params: &param,
                method: &method,
                data: data.as_deref(),
                cookies: &cookies,
                headers: &headers,
                bearer: bearer.as_deref(),
                json,
                program: program.as_deref(),
                handle: handle.as_deref(),
            };
            commands::xss::run(&url, i_authorize, opts).await
        }

        Commands::Payload {
            clause,
            quote,
            dbms,
            representation,
            tier,
            technique,
            waf,
            json,
        } => {
            commands::payload::run(
                &clause,
                &quote,
                dbms.as_deref(),
                &representation,
                &tier,
                &technique,
                waf,
                json,
            )
        }

        Commands::Sqli {
            input,
            i_authorize,
            cookies,
            cookie_file,
            headers,
            bearer,
            output,
            format,
            depth,
            max_requests,
            program,
            handle,
            ..
        } => {
            let opts = SqliOptions {
                cookies: &cookies,
                cookie_file: cookie_file.as_deref(),
                headers: &headers,
                bearer: bearer.as_deref(),
                output: output.as_deref(),
                format: &format,
                depth: &depth,
                max_requests,
                program: program.as_deref(),
                handle: handle.as_deref(),
            };
            commands::sqli::run(&input, i_authorize, opts).await
        }

        Commands::Endpoints {
            input,
            i_authorize,
            base,
            profile,
            depth,
            include_external,
            no_assets,
            kind,
            cookies,
            headers,
            bearer,
            rate_limit,
            max_requests,
            program,
            handle,
            json,
        } => {
            let opts = commands::endpoints::EndpointsOptions {
                i_authorize,
                base: base.as_deref(),
                profile: &profile,
                depth,
                include_external,
                include_assets: !no_assets,
                kind: kind.as_deref(),
                cookies: &cookies,
                headers: &headers,
                bearer: bearer.as_deref(),
                rate_limit,
                max_requests,
                program: program.as_deref(),
                handle: handle.as_deref(),
                json,
            };
            commands::endpoints::run(&input, opts).await
        }
    }
}
