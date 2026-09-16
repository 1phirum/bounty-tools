//! Native egui workstation. No webview, fixture telemetry, or animated controls.
use crate::bridge::{Action, Bridge, Message, ScanResultView, Snapshot, SubdomainEntry};
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
    /// Latest completed scan, rendered by the dashboard panels.
    pub last_scan: Option<ScanResultView>,
    /// Rolling history of completed scans for the history table.
    pub scan_history: Vec<ScanResultView>,
    /// Live-activity level filter (ALL / INFO / TEST / MATCH / ERROR).
    pub log_filter: String,
    /// HTTP method for the target request panel.
    pub sql_method: String,
    /// HTTP body for POST/PUT/PATCH requests.
    pub sql_body: String,
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
            last_scan: None,
            scan_history: Vec::new(),
            log_filter: "ALL".into(),
            sql_method: "GET".into(),
            sql_body: String::new(),
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
                Message::ScanComplete(view) => {
                    self.last_scan = Some(*view.clone());
                    self.scan_history.insert(0, *view);
                    self.busy = false;
                    self.status = "Scan complete".into();
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
    
    fn sql_activity(&mut self, ui: &mut egui::Ui) {
        ui.heading(RichText::new("Live Activity").size(22.0).color(CYAN));
        ui.horizontal_wrapped(|ui| {
            for level in ["ALL", "INFO", "TEST", "MATCH", "ERROR"] {
                let selected = self.log_filter == level;
                if ui.selectable_label(selected, level).clicked() {
                    self.log_filter = level.into();
                }
            }
        });
        ui.separator();
        egui::ScrollArea::vertical()
            .max_height(220.0)
            .stick_to_bottom(true)
            .show(ui, |ui| {
            let filter = self.log_filter.clone();
            let shown: Vec<&String> = self
                .sql_logs
                .iter()
                .filter(|l| {
                    filter == "ALL"
                        || match filter.as_str() {
                            "MATCH" => l.contains("[signal]") || l.contains("MATCH"),
                            "TEST" => l.contains("[*]") || l.contains("TEST") || l.contains("Probing"),
                            "INFO" => l.contains("[+]") || l.contains("INFO"),
                            "ERROR" => l.contains("ERROR") || l.contains("denied"),
                            _ => true,
                        }
                })
                .collect();
            if shown.is_empty() {
                ui.label(RichText::new("No active scan. Waiting for target...").color(MUTED));
            }
            for log in shown {
                ui.monospace(log);
            }
        });
    }

    fn sql_engine(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .id_salt("sql_main_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                // ── Target Request panel ─────────────────────────────────────────
                ui.add_space(6.0);
                ui.heading(RichText::new("SQL Engine").size(28.0).color(CYAN));
        ui.label(RichText::new("Scope-checked DBMS detection with clause coverage and explainable confidence.").color(MUTED));
        ui.add_space(10.0);

                let mut params = parse_query_params(&self.sql_filter);
                if ["POST", "PUT", "PATCH"].contains(&self.sql_method.as_str()) {
                    params.extend(parse_body_params(&self.sql_body));
                }

        egui::Frame::group(ui.style()).inner_margin(14.0).show(ui, |ui| {
            ui.label(RichText::new("TARGET REQUEST").small().color(MUTED));
            ui.scope(|ui| {
                ui.spacing_mut().interact_size.y = 44.0;
                ui.horizontal(|ui| {
                    egui::ComboBox::from_id_salt("sql_method")
                        .selected_text(&self.sql_method)
                        .width(128.0)
                        .icon(|ui, rect, _visuals, is_open, _above_or_below| {
                            let (uri, bytes) = if is_open {
                                ("bytes://chevron-up.svg", include_bytes!("../assets/chevron-up.svg").as_slice())
                            } else {
                                ("bytes://chevron-down.svg", include_bytes!("../assets/chevron-down.svg").as_slice())
                            };
                            egui::Image::from_bytes(uri, bytes).paint_at(ui, rect);
                        })
                        .show_ui(ui, |ui| {
                            for m in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] {
                                ui.selectable_value(&mut self.sql_method, m.into(), m);
                            }
                        });
                    ui.add_sized(
                        [ui.available_width() - 260.0, 44.0],
                        egui::TextEdit::singleline(&mut self.sql_filter)
                            .hint_text("https://host/path?id=42")
                            .margin(egui::vec2(12.0, 8.0))
                            .font(egui::TextStyle::Monospace),
                    );
                    let can_scan = !self.busy && !self.sql_filter.trim().is_empty();
                    if ui.add_enabled(
                        can_scan,
                        egui::Button::new(
                            RichText::new("▶ START SCAN")
                                .color(Color32::from_rgb(10, 14, 22))
                                .size(15.0),
                        )
                        .fill(CYAN)
                        .min_size(egui::vec2(120.0, 44.0)),
                    ).clicked() {
                        self.sql_logs.clear();
                        self.action(Action::SqlSimulate { target: self.sql_filter.trim().to_lowercase() });
                    }
                });
            });
            
            if ["POST", "PUT", "PATCH"].contains(&self.sql_method.as_str()) {
                ui.add_space(8.0);
                ui.label(RichText::new("REQUEST BODY").small().color(MUTED));
                ui.add(
                    egui::TextEdit::multiline(&mut self.sql_body)
                        .hint_text("Enter JSON or application/x-www-form-urlencoded data here...")
                        .desired_width(ui.available_width())
                        .font(egui::TextStyle::Monospace)
                        .margin(egui::vec2(12.0, 12.0)),
                );
            }

            ui.add_space(10.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.label(RichText::new("PARAMETERS").small().color(MUTED));
                ui.add_space(8.0);
                ui.label(RichText::new(format!("{} detected", params.len())).small().color(CYAN));
            });
            if params.is_empty() {
                ui.label(RichText::new("No query parameters. Add ?id=42 (the scan probes the first, or injects a marker).").color(MUTED));
            } else {
                egui::Grid::new("params_grid").num_columns(3).striped(true).show(ui, |ui| {
                    ui.strong("Parameter");
                    ui.strong("Value");
                    ui.strong("Context");
                    ui.end_row();
                    for (name, value) in &params {
                        ui.monospace(name);
                        ui.monospace(value);
                        ui.label(RichText::new(infer_context(value)).color(MUTED));
                        ui.end_row();
                    }
                });
            }
        });
        ui.add_space(8.0);

        // ── Results: three equal panels
        ui.columns(3, |cols| {
            egui::Frame::group(cols[0].style()).inner_margin(14.0).show(&mut cols[0], |ui| {
                ui.set_min_width((ui.available_width() - 28.0).max(0.0));
                ui.label(RichText::new("CLAUSE COVERAGE").small().color(MUTED));
                ui.add_space(6.0);
                match &self.last_scan {
                    None => { ui.label(RichText::new("Coverage appears after a DBMS is identified.").color(MUTED)); }
                    Some(scan) if scan.clause_coverage.is_empty() => {
                        ui.label(RichText::new("Coverage unavailable until a DBMS is identified.").color(MUTED));
                    }
                    Some(scan) => {
                        egui::Grid::new("clause_grid").num_columns(4).striped(true).show(ui, |ui| {
                            for chunk in scan.clause_coverage.chunks(2) {
                                for (clause, accepted) in chunk {
                                    let (icon, color) = if *accepted { ("✓", GREEN) } else { ("✕", RED) };
                                    ui.label(RichText::new(format!("{} {}", clause, icon)).color(color));
                                }
                                ui.end_row();
                            }
                        });
                    }
                }
            });
            egui::Frame::group(cols[1].style()).inner_margin(14.0).show(&mut cols[1], |ui| {
                ui.set_min_width((ui.available_width() - 28.0).max(0.0));
                ui.label(RichText::new("DATABASE INTELLIGENCE").small().color(MUTED));
                ui.add_space(6.0);
                match &self.last_scan {
                    None => { ui.label(RichText::new("No scan yet. Run a scan to identify the DBMS.").color(MUTED)); }
                    Some(scan) => {
                        ui.label(RichText::new(&scan.dbms_label).size(20.0).color(CYAN));
                        let frac = scan.confidence as f32 / 100.0;
                        ui.add(egui::ProgressBar::new(frac).text(format!("Confidence {}%", scan.confidence)).fill(CYAN));
                        ui.add_space(4.0);
                        if !scan.alternatives.is_empty() {
                            ui.label(RichText::new("Alternatives").small().color(MUTED));
                            for (name, score) in &scan.alternatives {
                                ui.monospace(format!("{}  {}%", name, score));
                            }
                        }
                        if scan.confidence > 0 {
                            ui.label(RichText::new(format!("Injection signal: {}", scan.verdict)).small().color(AMBER));
                        }
                    }
                }
            });
            egui::Frame::group(cols[2].style()).inner_margin(14.0).show(&mut cols[2], |ui| {
                ui.set_min_width((ui.available_width() - 28.0).max(0.0));
                ui.label(RichText::new("SIGNAL EXPLORER").small().color(MUTED));
                ui.add_space(6.0);
                match &self.last_scan {
                    None => { ui.label(RichText::new("Matched signatures appear here — why the engine reached its confidence.").color(MUTED)); }
                    Some(scan) if scan.signals.is_empty() => {
                        ui.label(RichText::new("No DBMS-specific signatures matched.").color(MUTED));
                    }
                    Some(scan) => {
                        egui::ScrollArea::vertical().id_salt("signals").max_height(180.0).show(ui, |ui| {
                            for (label, dbms, weight, category) in &scan.signals {
                                egui::Frame::group(ui.style()).inner_margin(8.0).show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.monospace(label);
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            ui.label(RichText::new(format!("+{}", weight)).color(CYAN));
                                        });
                                    });
                                    ui.label(RichText::new(format!("{} · {}", dbms, category)).small().color(MUTED));
                                });
                            }
                        });
                    }
                }
            });
        });
        ui.add_space(8.0);

        // ── Scan History ─────────────────────────────────────────────────
        if !self.scan_history.is_empty() {
            let panel_width = ui.available_width();
            egui::Frame::group(ui.style()).inner_margin(14.0).show(ui, |ui| {
                ui.set_min_width((panel_width - 28.0).max(0.0));
                ui.label(RichText::new("SCAN HISTORY").small().color(MUTED));
                egui::Grid::new("history_grid").num_columns(4).striped(true).show(ui, |ui| {
                    ui.strong("Target"); ui.strong("Param"); ui.strong("DBMS"); ui.strong("Confidence");
                    ui.end_row();
                    for scan in self.scan_history.iter().take(10) {
                        ui.monospace(truncate(&scan.target, 34));
                        ui.monospace(&scan.parameter);
                        ui.label(&scan.dbms_label);
                        ui.monospace(format!("{}%", scan.confidence));
                        ui.end_row();
                    }
                });
            });
        }

        // ── Scan summary bar ─────────────────────────────────────────────
        if let Some(scan) = &self.last_scan {
            ui.add_space(6.0);
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                ui.monospace(format!("PROBES {}", scan.probes_run));
                ui.separator();
                ui.monospace(format!("CONFIDENCE {}%", scan.confidence));
                ui.separator();
                ui.monospace(format!("DBMS {}", scan.dbms_label.to_uppercase()));
                ui.separator();
                ui.monospace(format!("VERDICT {}", scan.verdict.to_uppercase()));
            });
        }

        ui.add_space(16.0);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            self.sql_activity(ui);
        });
        }); // close ScrollArea
    }
}

/// Extract (name, value) query pairs from a URL for the parameter table.
fn parse_query_params(url: &str) -> Vec<(String, String)> {
    url::Url::parse(url.trim())
        .ok()
        .map(|u| {
            u.query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Extract (name, value) pairs from request body (JSON or urlencoded).
fn parse_body_params(body: &str) -> Vec<(String, String)> {
    let body = body.trim();
    if body.is_empty() {
        return vec![];
    }
    
    // Try parsing as JSON first
    if body.starts_with('{') {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(map) = json.as_object() {
                return map.into_iter().map(|(k, v)| {
                    let val_str = match v {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Null => "null".to_string(),
                        other => other.to_string(),
                    };
                    (k.clone(), val_str)
                }).collect();
            }
        }
    }
    
    // Fallback to x-www-form-urlencoded
    url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect()
}

/// Infer the SQL injection context from a parameter's value (numeric vs
/// string). Shown in the parameter table — maps to the engine's SqlContext.
fn infer_context(value: &str) -> &'static str {
    if value.chars().all(|c| c.is_ascii_digit()) && !value.is_empty() {
        "Numeric"
    } else if value.is_empty() {
        "Unknown"
    } else {
        "String"
    }
}

/// Truncate a string for table display.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{}…", t)
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

                match self.active_tab {
                    Tab::SubdomainFinder => self.subdomain_finder(ui),
                    Tab::SqlEngine => self.sql_engine(ui),
                }
            });
    }
}
