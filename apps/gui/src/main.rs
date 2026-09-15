#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod process;
mod state;

use eframe::egui;

#[derive(PartialEq, Clone, Copy)]
enum View {
    Projects,
    Scope,
    Recon,
    Traffic,
    Findings,
    Settings,
}

struct BugToolsApp {
    current_view: View,
}

impl BugToolsApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        egui_extras::install_image_loaders(&cc.egui_ctx);

        // Apply a dark visual theme
        let mut style = (*cc.egui_ctx.style()).clone();
        style.visuals = egui::Visuals::dark();
        cc.egui_ctx.set_style(style);

        Self {
            current_view: View::Projects,
        }
    }

    fn render_nav_button(&mut self, ui: &mut egui::Ui, view: View, label: &str, image: egui::ImageSource<'_>) {
        let is_selected = self.current_view == view;
        let mut button = egui::Button::image_and_text(
            egui::Image::new(image).max_height(16.0),
            label,
        )
        .selected(is_selected);
        
        if ui.add_sized([ui.available_width(), 30.0], button).clicked() {
            self.current_view = view;
        }
    }
}

impl eframe::App for BugToolsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::SidePanel::left("nav_panel")
            .exact_width(160.0)
            .show(ctx, |ui| {
                ui.add_space(10.0);
                ui.heading("BugTools");
                ui.label("Security Workstation");
                ui.add_space(20.0);
                
                ui.separator();
                
                ui.add_space(10.0);
                self.render_nav_button(ui, View::Projects, "Projects", egui::include_image!("../assets/projects.svg"));
                self.render_nav_button(ui, View::Scope, "Scope", egui::include_image!("../assets/scope.svg"));
                self.render_nav_button(ui, View::Recon, "Recon", egui::include_image!("../assets/recon.svg"));
                self.render_nav_button(ui, View::Traffic, "Traffic", egui::include_image!("../assets/traffic.svg"));
                self.render_nav_button(ui, View::Findings, "Findings", egui::include_image!("../assets/findings.svg"));
                self.render_nav_button(ui, View::Settings, "Settings", egui::include_image!("../assets/settings.svg"));
            });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(10.0);
            match self.current_view {
                View::Projects => {
                    ui.heading("Projects");
                    ui.label("Project list will appear here.");
                }
                View::Scope => {
                    ui.heading("Scope & Targets");
                    ui.label("Scope rules and targets will appear here.");
                }
                View::Recon => {
                    ui.heading("Reconnaissance");
                    ui.label("Recon scans and active jobs will appear here.");
                }
                View::Traffic => {
                    ui.heading("HTTP Traffic");
                    ui.label("Proxy traffic and repeater will appear here.");
                }
                View::Findings => {
                    ui.heading("Findings");
                    ui.label("Vulnerabilities and notes will appear here.");
                }
                View::Settings => {
                    ui.heading("Settings");
                    ui.label("Global configuration and rate limits will appear here.");
                }
            }
        });
    }
}

fn main() -> eframe::Result<()> {
    eprintln!("[bugtools] Starting minimal GUI test (No DB)...");

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_min_inner_size([800.0, 600.0]),
        renderer: eframe::Renderer::Wgpu,
        ..Default::default()
    };

    eframe::run_native(
        "BugTools - Security Research Workstation",
        native_options,
        Box::new(|cc| Ok(Box::new(BugToolsApp::new(cc)))),
    )
}
