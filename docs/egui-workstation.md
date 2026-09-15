# Native egui workstation

## Run

From the repository root:

```sh
cargo run -p bugtools-gui
```

The application is a native egui/eframe 0.29 workstation; no Node, React, webview or Tauri IPC is needed. Use stable Rust and a C/C++ linker. The events crate needs `protoc` on PATH or `PROTOC` set to its executable. On Windows the existing repository-local `.bin/protoc/bin/protoc.exe` is also recognized; the build no longer assumes `C:\bug-tools`.

`BUGTOOLS_DB_PATH` overrides the default `workspace/projects/bugtools.db`. Missing parent directories are created by the backend worker. Database initialization errors are shown in the GUI. Projects, scope rules and findings persist in SQLite. HTTP exchanges are session-wide and memory-only, not per-project.

## Implemented

- Dark, fixed-geometry navigation, monospace request data, striped/resizable HTTP tables, error banners and static status text. No hover expansion, animation, pulsing or fake telemetry.
- Overview populated from real database/store snapshots.
- Project creation and selection, synchronized with project scope rules. Failed selection clears stale authorization.
- Scope rule creation and offline target evaluation. An explicit domain inclusion is mandatory; exclusions take precedence.
- Scoped single-host DNS resolution and scheduler job list. No port scan is performed.
- HTTP history filters, request/response inspector, confirmed clear, copy-to-composer for manual replay.
- Header JSON validation, manual HTTP sends via the shared safe client, timeout/error reporting. PATCH and OPTIONS preserve their methods. Redirects are returned without following. HTTP response headers/body are capped at 2 MiB.
- SQL research: offline pasted-error signal review and searchable, expandable dialect catalog. Signals and existing catalog entries are not proof of a target DBMS, version, vulnerability or clause support.
- Candidate finding creation, filtering and inspection.
- Active-project Markdown report export. Existing destination files are never overwritten. Raw traffic is excluded; user notes must still be reviewed for secrets.
- Compact/comfortable density and optional local snapshot refresh. These appearance choices currently last for the session.

## Architecture

`workstation.rs` owns egui state and renders cached snapshots. `bridge.rs` serializes commands through an mpsc worker with a Tokio runtime; database and network operations do not run on the paint thread. Completion wakes egui. Network actions require an active project, synchronized scope and an explicit matching rule. User actions are disabled while work is in progress.

## Deliberately not claimed as complete

External recon worker launch/cancellation, automated fuzz runs, active SQL injection/timing probes, a listening/intercepting proxy, persistent HTTP evidence, finding edit/delete, and editable backend network limits are not connected in this GUI release. The legacy backend modules remain in the repository; no UI button claims that these capabilities succeeded. The SQL catalog and detector inherited from earlier work still require semantic/version validation before operational use.

The UI's DNS action resolves a hostname only. Its lookup can time out; OS resolver work may finish later. Scope is host/path based, not a DNS-rebinding defense. HTTP byte limits apply to retained headers/body, not reqwest's internal wire buffers.

## Validation

Executed on Linux with a real Rust compiler:

```sh
cargo check -p bugtools-gui
cargo build -p bugtools-gui
cargo test -p bugtools-gui -p bugtools-http -p bugtools-scope -p bugtools-storage
```

37 tests passed (GUI/bridge: 8; HTTP: 21; scope: 6; storage: 2). A native window was launched under Xvfb with software graphics and visually inspected. The tests cover all ten page layouts at compact and desktop widths, style stability, project/scope isolation, finding/report workflow, header validation, non-overwrite export, DB startup, HTTP limits and default-deny scope. This is not a Windows packaging or GPU compatibility certification.
