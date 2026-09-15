#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod process;
mod state;

mod bridge;
mod workstation;

fn main() -> eframe::Result<()> {
    let db_path = std::env::var_os("BUGTOOLS_DB_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("workspace/projects/bugtools.db"));
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([960.0, 640.0]),
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };
    eframe::run_native(
        "BugTools - Security Research Workstation",
        options,
        Box::new(move |cc| Ok(Box::new(workstation::Workstation::new(cc, db_path)))),
    )
}
