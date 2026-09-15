//! Native egui workstation. No webview, fixture telemetry, or animated controls.
use crate::bridge::{Action, Bridge, Message, Snapshot, SubdomainEntry};
use eframe::egui::{self, Color32, RichText};
use std::{
    path::PathBuf,
};

const CYAN: Color32 = Color32::from_rgb(44, 206, 219);
const MUTED: Color32 = Color32::from_rgb(151, 170, 190);
const BORDER: Color32 = Color32::from_rgb(45, 59, 77);
const GREEN: Color32 = Color32::from_rgb(85, 214, 158);
const RED: Color32 = Color32::from_rgb(251, 119, 131);
const AMBER: Color32 = Color32::from_rgb(246, 199, 101);

#[derive(PartialEq)]
enum Tab {
    SubdomainFinder,
    SqlEngine,
}

pub struct Workstation {
    bridge: Bridge,
    data: Snapshot,
    busy: bool,
    ready: bool,
    status: String,
    error: Option<String>,
    
    // UI state
    status_modal: Option<(String, String)>,
    active_tab: Tab,
    
    // Subdomain Finder State
    pub target_domain: String,
    pub subdomains: Vec<SubdomainEntry>,
    
    // SQL Engine State
    pub sql_filter: String,
    pub sql_logs: Vec<String>,
}

pub fn configure(ctx: &egui::Context, compact: bool) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "Roboto".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/Roboto-Variable.ttf")),
    );
    fonts.families.entry(egui::FontFamily::Proportional).or_default().insert(0, "Roboto".to_owned());
    fonts.families.insert(egui::FontFamily::Name("Heading".into()), vec!["Roboto".to_owned()]);
    ctx.set_fonts(fonts);

    ctx.set_theme(egui::Theme::Dark);
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.animation_time = 0.0;
    style.spacing.item_spacing = egui::vec2(12.0, if compact { 8.0 } else { 16.0 });
    style.spacing.button_padding = egui::vec2(14.0, 8.0);
    style.spacing.interact_size.y = 32.0;
    style.visuals.panel_fill = Color32::from_rgb(10, 14, 22); 
    style.visuals.window_fill = Color32::from_rgb(18, 26, 39);
    style.visuals.extreme_bg_color = Color32::from_rgb(9, 14, 22);
    style.visuals.faint_bg_color = Color32::from_rgb(16, 23, 34); 
    style.visuals.override_text_color = Some(Color32::from_rgb(220, 230, 240));
    style.visuals.selection.bg_fill = Color32::from_rgb(22, 65, 82);
    style.visuals.selection.stroke = egui::Stroke::new(1.0, CYAN);
    for widget in [
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
    ] {
        widget.expansion = 0.0;
        widget.rounding = egui::Rounding::same(6.0); 
        widget.bg_stroke = egui::Stroke::new(1.0, BORDER);
        widget.weak_bg_fill = Color32::from_rgb(24, 35, 49);
        widget.bg_fill = Color32::from_rgb(24, 35, 49);
    }
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(38, 55, 74); 
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(26, 67, 82);
    style
        .text_styles
        .insert(egui::TextStyle::Heading, egui::FontId::new(32.0, egui::FontFamily::Name("Heading".into())));
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(16.0)); 
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::proportional(16.0));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(15.0)); 
    ctx.set_style(style);
}

impl Workstation {
    pub fn new(cc: &eframe::CreationContext<'_>, db_path: PathBuf) -> Self {
        Self::with_context(&cc.egui_ctx, db_path)
    }
    fn with_context(ctx: &egui::Context, db_path: PathBuf) -> Self {
        egui_extras::install_image_loaders(ctx);
        configure(ctx, true);
        let bridge = Bridge::start(db_path.clone(), ctx.clone());
        bridge.send(Action::Refresh);
        Self {
            bridge,
            data: Snapshot::default(),
            busy: true,
            ready: false,
            status: "Ready".into(),
            error: None,
            status_modal: None,

            active_tab: Tab::SubdomainFinder,
            
            target_domain: String::new(),
            subdomains: Vec::new(),
            sql_filter: String::new(),
            sql_logs: Vec::new(),
        }
    }
    fn action(&mut self, action: Action) {
        self.busy = true;
        self.error = None;
        self.status = "Working…".into();
        self.bridge.send(action);
        self.bridge.send(Action::Refresh);
    }
    fn receive(&mut self) {
        while let Some(message) = self.bridge.try_recv() {
            match message {
                Message::Snapshot(data) => {
                    self.data = data;
                    self.busy = false;
                    self.ready = true;
                    if self.error.is_none() {
                        self.status = "Ready".into();
                    }
                }
                Message::Output { title, text } => {
                    self.status_modal = Some((title, text));
                    self.busy = false;
                }
                Message::Subdomains(results) => {
                    self.subdomains = results;
                    self.busy = false;
                    self.status = "Mapping complete".into();
                }
                Message::LiveLog(log) => {
                    self.sql_logs.push(log);
                }
                Message::Error(error) => {
                    self.busy = false;
                    self.status = "Action failed".into();
                    self.error = Some(error);
                }
            }
        }
    }
    
    fn subdomain_finder(&mut self, ui: &mut egui::Ui) {
        // Left side: Scan controls (fixed 300px)
        egui::SidePanel::left("scan_panel")
            .exact_width(300.0)
            .resizable(false)
            .show_inside(ui, |ui| {
                ui.add_space(30.0);
                ui.vertical_centered(|ui| {
                    ui.heading(RichText::new("Subdomain Finder").size(24.0).color(CYAN));
                    ui.add_space(6.0);
                    ui.label(RichText::new("Certificate Transparency scan").color(MUTED));
                });
                
                ui.add_space(20.0);
                
                ui.label(RichText::new("Target Domain").color(CYAN));
                ui.add_space(4.0);
                let res = ui.add(
                    egui::TextEdit::singleline(&mut self.target_domain)
                        .hint_text("example.com")
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 8.0))
                );
                
                ui.add_space(12.0);
                
                if ui.add_sized(
                    [ui.available_width(), 38.0],
                    egui::Button::new(RichText::new("Map Subdomains").color(Color32::from_rgb(10, 14, 22))).fill(CYAN)
                ).clicked() || (res.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                    let domain = self.target_domain.trim().to_string();
                    if !domain.is_empty() && !self.busy {
                        self.action(Action::MapSubdomains { target: domain });
                    }
                }
                
                ui.add_space(16.0);
                
                if self.busy {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new("Scanning...").color(CYAN));
                    });
                }
                
                if !self.subdomains.is_empty() && !self.busy {
                    ui.label(RichText::new(format!("{} subdomains found", self.subdomains.len())).color(GREEN));
                    
                    ui.add_space(12.0);
                    
                    if ui.add_sized(
                        [ui.available_width(), 34.0],
                        egui::Button::new(RichText::new("Export JSON").color(Color32::from_rgb(10, 14, 22))).fill(CYAN)
                    ).clicked() {
                        if let Some(folder) = rfd::FileDialog::new()
                            .set_title("Choose export folder")
                            .pick_folder()
                        {
                            let domain = self.target_domain.trim().replace('.', "_");
                            let json_path = folder.join(format!("{}_subdomains.json", domain));
                            let json = serde_json::json!({
                                "target": self.target_domain.trim(),
                                "total": self.subdomains.len(),
                                "subdomains": self.subdomains,
                            });
                            if let Ok(content) = serde_json::to_string_pretty(&json) {
                                let _ = std::fs::write(&json_path, &content);
                                self.status = format!("Exported to {}", json_path.display());
                            }
                        }
                    }
                }
            });

        // Right side: Results table (fills remaining space)
        egui::Frame::none()
            .inner_margin(egui::Margin { left: 24.0, right: 16.0, top: 24.0, bottom: 16.0 })
            .show(ui, |ui| {
                if self.subdomains.is_empty() && !self.busy {
                    ui.vertical_centered(|ui| {
                        ui.add_space(150.0);
                        ui.label(RichText::new("No results yet").size(20.0).color(MUTED));
                        ui.label(RichText::new("Enter a domain and scan.").color(MUTED));
                    });
                } else {
                    egui_extras::TableBuilder::new(ui)
                        .striped(true)
                        .resizable(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(egui_extras::Column::initial(40.0).at_least(30.0)) // ID
                        .column(egui_extras::Column::initial(300.0).at_least(100.0).clip(true)) // Domain
                        .column(egui_extras::Column::initial(150.0).at_least(80.0).clip(true)) // First Seen
                        .column(egui_extras::Column::initial(200.0).at_least(100.0).clip(true)) // Issuer
                        .column(egui_extras::Column::remainder().at_least(80.0).clip(true)) // Cert ID
                        .min_scrolled_height(0.0)
                        .header(28.0, |mut header| {
                            header.col(|ui| { ui.label(RichText::new("ID").color(CYAN).strong()); });
                            header.col(|ui| { ui.label(RichText::new("Domain").color(CYAN).strong()); });
                            header.col(|ui| { ui.label(RichText::new("First Seen").color(CYAN).strong()); });
                            header.col(|ui| { ui.label(RichText::new("Issuer").color(CYAN).strong()); });
                            header.col(|ui| { ui.label(RichText::new("Cert ID").color(CYAN).strong()); });
                        })
                        .body(|mut body| {
                            for (i, entry) in self.subdomains.iter().enumerate() {
                                body.row(24.0, |mut row| {
                                    row.col(|ui| { ui.label(RichText::new(format!("{}", i + 1)).color(MUTED).monospace()); });
                                    row.col(|ui| { ui.monospace(&entry.domain); });
                                    row.col(|ui| { ui.label(RichText::new(&entry.first_seen).color(MUTED)); });
                                    row.col(|ui| { ui.label(RichText::new(&entry.issuer).color(MUTED)); });
                                    row.col(|ui| { ui.label(RichText::new(format!("{}", entry.cert_id)).color(MUTED).monospace()); });
                                });
                            }
                        });
                }
            });
    }
    
    fn sql_engine(&mut self, ui: &mut egui::Ui) {
        egui::SidePanel::right("sql_logs")
            .min_width(350.0)
            .show_inside(ui, |ui| {
                ui.heading(RichText::new("Live Logs").color(CYAN));
                ui.separator();
                egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                    if self.sql_logs.is_empty() {
                        ui.label(RichText::new("No active scan. Waiting for target...").color(MUTED));
                    }
                    for log in &self.sql_logs {
                        ui.monospace(log);
                    }
                });
            });

        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.heading(RichText::new("SQL Engine").size(48.0).color(CYAN));
            ui.add_space(10.0);
            ui.label(RichText::new("Automated SQL scanner and reference").color(MUTED));
            
            ui.add_space(40.0);
            
            ui.horizontal(|ui| {
                let available_width = ui.available_width();
                let search_bar_width = 700.0_f32.min(available_width);
                ui.add_space((available_width - search_bar_width) / 2.0);
                
                let res = ui.add(
                    egui::TextEdit::singleline(&mut self.sql_filter)
                        .hint_text("Target URL with a query param (e.g. https://host/path?id=1) — Live Scan probes the first param")
                        .desired_width(search_bar_width - 110.0)
                        .margin(egui::vec2(12.0, 12.0))
                );
                
                ui.add_space(10.0);
                
                let query = self.sql_filter.to_lowercase();
                
                if ui.add_sized(
                    [100.0, 42.0],
                    egui::Button::new(RichText::new("Live Scan").color(Color32::from_rgb(10, 14, 22))).fill(CYAN)
                ).clicked() || (res.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                    // Live Scan runs the real, scope-checked DBMS probe
                    // pipeline. No output is fabricated — logs come from the
                    // actual per-probe results.
                    self.sql_logs.clear();
                    self.action(Action::SqlSimulate { target: query.clone() });
                }
            });
        });
    }
}

impl eframe::App for Workstation {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive();
        
        egui::TopBottomPanel::top("toolbar")
            .exact_height(52.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.strong(RichText::new("BUGTOOLS").color(CYAN));
                    ui.separator();
                    ui.selectable_value(&mut self.active_tab, Tab::SubdomainFinder, "Subdomain Finder");
                    ui.selectable_value(&mut self.active_tab, Tab::SqlEngine, "SQL Engine");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(if self.busy {
                                "WORKING"
                            } else if self.ready {
                                "READY"
                            } else {
                                "OFFLINE"
                            })
                            .monospace()
                            .color(if self.ready {
                                GREEN
                            } else {
                                AMBER
                            }),
                        );
                    });
                });
            });
            
        egui::TopBottomPanel::bottom("status")
            .exact_height(28.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.monospace(&self.status);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new("RUST + EGUI")
                                .small()
                                .color(MUTED),
                        );
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).inner_margin(32.0))
            .show(ctx, |ui| {
                if let Some(error) = self.error.clone() {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.colored_label(RED, &error);
                            if ui.small_button("Dismiss").clicked() {
                                self.error = None;
                            }
                        });
                    });
                }
                
                if let Some((title, text)) = self.status_modal.clone() {
                    egui::Window::new(title)
                        .collapsible(false)
                        .resizable(true)
                        .show(ctx, |ui| {
                            egui::ScrollArea::vertical().show(ui, |ui| {
                                ui.label(text);
                            });
                            if ui.button("Dismiss").clicked() {
                                self.status_modal = None;
                            }
                        });
                }

                egui::ScrollArea::vertical()
                    .id_salt("page")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        match self.active_tab {
                            Tab::SubdomainFinder => self.subdomain_finder(ui),
                            Tab::SqlEngine => self.sql_engine(ui),
                        }
                    });
            });
    }
}
