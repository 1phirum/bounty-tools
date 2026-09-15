//! Native egui workstation. No webview, fixture telemetry, or animated controls.
use crate::bridge::{Action, Bridge, Message, Snapshot};
use eframe::egui::{self, Color32, RichText, TextEdit};
use egui_extras::{Column, TableBuilder};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use uuid::Uuid;

const CYAN: Color32 = Color32::from_rgb(44, 206, 219);
const MUTED: Color32 = Color32::from_rgb(151, 170, 190);
const BORDER: Color32 = Color32::from_rgb(45, 59, 77);
const GREEN: Color32 = Color32::from_rgb(85, 214, 158);
const RED: Color32 = Color32::from_rgb(251, 119, 131);
const AMBER: Color32 = Color32::from_rgb(246, 199, 101);

#[derive(Clone, Copy, PartialEq, Debug)]
enum View {
    Dashboard,
    Projects,
    Scope,
    Recon,
    Traffic,
    Repeater,
    Sql,
    Findings,
    Reports,
    Settings,
}
impl View {
    const ALL: [Self; 10] = [
        Self::Dashboard,
        Self::Projects,
        Self::Scope,
        Self::Recon,
        Self::Traffic,
        Self::Repeater,
        Self::Sql,
        Self::Findings,
        Self::Reports,
        Self::Settings,
    ];
    fn label(self) -> &'static str {
        match self {
            Self::Dashboard => "Overview",
            Self::Projects => "Projects",
            Self::Scope => "Scope & targets",
            Self::Recon => "Recon & jobs",
            Self::Traffic => "HTTP history",
            Self::Repeater => "Request composer",
            Self::Sql => "SQL research",
            Self::Findings => "Findings",
            Self::Reports => "Reports",
            Self::Settings => "Settings",
        }
    }
}

pub struct Workstation {
    bridge: Bridge,
    data: Snapshot,
    view: View,
    busy: bool,
    ready: bool,
    status: String,
    error: Option<String>,
    activity: Vec<String>,
    project_name: String,
    project_description: String,
    scope_kind: String,
    scope_pattern: String,
    scope_target: String,
    url: String,
    method: String,
    headers: String,
    body: String,
    traffic_filter: String,
    selected_traffic: Option<Uuid>,
    response_tab: bool,
    finding_title: String,
    finding_target: String,
    finding_notes: String,
    finding_severity: String,
    selected_finding: Option<Uuid>,
    finding_filter: String,
    export_path: String,
    output: String,
    output_title: String,
    sql_input: String,
    sql_result: String,
    sql_filter: String,
    clear_confirm: bool,
    compact: bool,
    auto_refresh: bool,
    last_refresh: Instant,
    db_path: PathBuf,
}

pub fn configure(ctx: &egui::Context, compact: bool) {
    ctx.set_theme(egui::Theme::Dark);
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.animation_time = 0.0;
    style.spacing.item_spacing = egui::vec2(8.0, if compact { 5.0 } else { 9.0 });
    style.spacing.button_padding = egui::vec2(10.0, 6.0);
    style.spacing.interact_size.y = 28.0;
    style.visuals.panel_fill = Color32::from_rgb(14, 20, 30);
    style.visuals.window_fill = Color32::from_rgb(18, 26, 39);
    style.visuals.extreme_bg_color = Color32::from_rgb(9, 14, 22);
    style.visuals.faint_bg_color = Color32::from_rgb(20, 29, 43);
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
        widget.rounding = egui::Rounding::same(4.0);
        widget.bg_stroke = egui::Stroke::new(1.0, BORDER);
        widget.weak_bg_fill = Color32::from_rgb(24, 35, 49);
        widget.bg_fill = Color32::from_rgb(24, 35, 49);
    }
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(33, 48, 64);
    style.visuals.widgets.active.bg_fill = Color32::from_rgb(26, 67, 82);
    style
        .text_styles
        .insert(egui::TextStyle::Body, egui::FontId::proportional(13.0));
    style
        .text_styles
        .insert(egui::TextStyle::Button, egui::FontId::proportional(13.0));
    style
        .text_styles
        .insert(egui::TextStyle::Monospace, egui::FontId::monospace(12.0));
    ctx.set_style(style);
}

impl Workstation {
    pub fn new(cc: &eframe::CreationContext<'_>, db_path: PathBuf) -> Self {
        Self::with_context(&cc.egui_ctx, db_path)
    }
    fn with_context(ctx: &egui::Context, db_path: PathBuf) -> Self {
        configure(ctx, true);
        let bridge = Bridge::start(db_path.clone(), ctx.clone());
        bridge.send(Action::Refresh);
        Self {
            bridge,
            data: Snapshot::default(),
            view: View::Dashboard,
            busy: true,
            ready: false,
            status: "Opening local workspace…".into(),
            error: None,
            activity: vec![],
            project_name: String::new(),
            project_description: String::new(),
            scope_kind: "include_domain".into(),
            scope_pattern: String::new(),
            scope_target: String::new(),
            url: String::new(),
            method: "GET".into(),
            headers: "{}".into(),
            body: String::new(),
            traffic_filter: String::new(),
            selected_traffic: None,
            response_tab: true,
            finding_title: String::new(),
            finding_target: String::new(),
            finding_notes: String::new(),
            finding_severity: "INFO".into(),
            selected_finding: None,
            finding_filter: String::new(),
            export_path: "bugtools-report.md".into(),
            output: String::new(),
            output_title: String::new(),
            sql_input: String::new(),
            sql_result: String::new(),
            sql_filter: String::new(),
            clear_confirm: false,
            compact: true,
            auto_refresh: false,
            last_refresh: Instant::now(),
            db_path,
        }
    }
    fn action(&mut self, action: Action) {
        self.busy = true;
        self.error = None;
        self.status = "Working…".into();
        self.bridge.send(action);
        self.bridge.send(Action::Refresh);
        self.last_refresh = Instant::now();
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
                    self.activity.push(format!(
                        "{}  {}",
                        chrono::Local::now().format("%H:%M:%S"),
                        title
                    ));
                    if self.activity.len() > 100 {
                        self.activity.remove(0);
                    }
                    self.output_title = title;
                    self.output = text;
                }
                Message::Error(error) => {
                    self.busy = false;
                    self.status = "Action failed".into();
                    self.error = Some(error);
                }
            }
        }
    }
    fn active_name(&self) -> String {
        self.data
            .projects
            .iter()
            .find(|p| Some(p.id) == self.data.active_project)
            .map(|p| p.name.clone())
            .unwrap_or_else(|| "Select a project".into())
    }
    fn can_act(&self) -> bool {
        self.ready && !self.busy && self.data.active_project.is_some()
    }
    fn heading(ui: &mut egui::Ui, title: &str, help: &str) {
        ui.add_space(8.0);
        ui.heading(RichText::new(title).size(23.0));
        ui.label(RichText::new(help).color(MUTED));
        ui.add_space(12.0);
        ui.separator();
        ui.add_space(10.0);
    }
    fn empty(ui: &mut egui::Ui, message: &str) {
        egui::Frame::group(ui.style())
            .inner_margin(20.0)
            .show(ui, |ui| {
                ui.label(RichText::new(message).color(MUTED));
            });
    }
    fn output_panel(&mut self, ui: &mut egui::Ui) {
        if !self.output.is_empty() {
            ui.separator();
            ui.horizontal(|ui| {
                ui.strong(&self.output_title);
                if ui.button("Copy result").clicked() {
                    ui.output_mut(|o| o.copied_text = self.output.clone());
                }
            });
            egui::ScrollArea::vertical()
                .id_salt("operation-output")
                .max_height(190.0)
                .show(ui, |ui| {
                    ui.add(
                        TextEdit::multiline(&mut self.output)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .interactive(false),
                    );
                });
        }
    }
    fn overview(&mut self, ui: &mut egui::Ui) {
        Self::heading(
            ui,
            "Workspace overview",
            "Local evidence, explicit scope, and a native Rust command path.",
        );
        ui.columns(4, |cols| {
            for (col, (label, count)) in cols.iter_mut().zip([
                ("PROJECTS", self.data.projects.len()),
                ("SCOPE RULES", self.data.rules.len()),
                ("HTTP EXCHANGES", self.data.total_traffic),
                ("FINDINGS", self.data.findings.len()),
            ]) {
                egui::Frame::group(col.style())
                    .inner_margin(14.0)
                    .show(col, |ui| {
                        ui.label(RichText::new(label).small().color(MUTED));
                        ui.label(
                            RichText::new(count.to_string())
                                .monospace()
                                .size(28.0)
                                .color(CYAN),
                        );
                    });
            }
        });
        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ui.button("Create / select project").clicked() {
                self.view = View::Projects;
            }
            if ui.button("Review scope").clicked() {
                self.view = View::Scope;
            }
            if ui.button("Compose request").clicked() {
                self.view = View::Repeater;
            }
        });
        ui.add_space(14.0);
        ui.strong("Session activity");
        if self.activity.is_empty() {
            Self::empty(ui, "No activity yet. Create a project to start.");
        }
        for event in self.activity.iter().rev().take(15) {
            ui.monospace(event);
        }
        ui.add_space(16.0);
        ui.colored_label(MUTED, "No background scanning. HTTP history is session-wide and memory-only. Findings and projects persist in SQLite.");
    }
    fn projects(&mut self, ui: &mut egui::Ui) {
        Self::heading(
            ui,
            "Projects",
            "Create a local workspace, then load its scope rules and findings.",
        );
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.label("Project name");
            ui.add(TextEdit::singleline(&mut self.project_name).desired_width(400.0));
            ui.label("Description");
            ui.add(
                TextEdit::multiline(&mut self.project_description)
                    .desired_rows(2)
                    .desired_width(f32::INFINITY),
            );
            if ui
                .add_enabled(
                    !self.busy && !self.project_name.trim().is_empty(),
                    egui::Button::new("Create project"),
                )
                .clicked()
            {
                self.action(Action::CreateProject {
                    name: self.project_name.trim().into(),
                    description: self.project_description.clone(),
                });
            }
        });
        ui.add_space(12.0);
        let mut select = None;
        if self.data.projects.is_empty() {
            Self::empty(
                ui,
                "No projects in this database. Create your first project above.",
            );
        }
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::remainder())
            .column(Column::remainder())
            .column(Column::exact(100.0))
            .header(26.0, |mut h| {
                for label in ["PROJECT", "DESCRIPTION", "STATE"] {
                    h.col(|ui| {
                        ui.strong(label);
                    });
                }
            })
            .body(|body| {
                body.rows(30.0, self.data.projects.len(), |mut row| {
                    let p = &self.data.projects[row.index()];
                    row.col(|ui| {
                        if ui
                            .selectable_label(Some(p.id) == self.data.active_project, &p.name)
                            .clicked()
                            && !self.busy
                        {
                            select = Some(p.id);
                        }
                    });
                    row.col(|ui| {
                        ui.label(&p.description);
                    });
                    row.col(|ui| {
                        ui.colored_label(
                            if Some(p.id) == self.data.active_project {
                                GREEN
                            } else {
                                MUTED
                            },
                            if Some(p.id) == self.data.active_project {
                                "ACTIVE"
                            } else {
                                "AVAILABLE"
                            },
                        );
                    });
                });
            });
        if let Some(id) = select {
            self.action(Action::SelectProject { id });
        }
    }
    fn scope(&mut self, ui: &mut egui::Ui) {
        Self::heading(ui, "Scope & targets", "Default deny. A matching domain inclusion is required; explicit exclusions take priority.");
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("scope-kind")
                .selected_text(&self.scope_kind)
                .show_ui(ui, |ui| {
                    for kind in [
                        "include_domain",
                        "exclude_domain",
                        "include_path",
                        "exclude_path",
                        "include_port",
                        "exclude_port",
                        "protocol",
                    ] {
                        ui.selectable_value(&mut self.scope_kind, kind.into(), kind);
                    }
                });
            ui.add(
                TextEdit::singleline(&mut self.scope_pattern)
                    .hint_text("example.com or *.example.com")
                    .desired_width(300.0),
            );
            if ui
                .add_enabled(
                    self.can_act() && !self.scope_pattern.trim().is_empty(),
                    egui::Button::new("Add rule"),
                )
                .clicked()
            {
                self.action(Action::AddScope {
                    kind: self.scope_kind.clone(),
                    pattern: self.scope_pattern.trim().into(),
                });
            }
        });
        ui.add_space(10.0);
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::exact(160.0))
            .column(Column::remainder())
            .column(Column::exact(85.0))
            .header(26.0, |mut h| {
                for s in ["RULE TYPE", "PATTERN", "STATE"] {
                    h.col(|ui| {
                        ui.strong(s);
                    });
                }
            })
            .body(|body| {
                body.rows(28.0, self.data.rules.len(), |mut row| {
                    let r = &self.data.rules[row.index()];
                    row.col(|ui| {
                        ui.monospace(format!("{:?}", r.rule_type));
                    });
                    row.col(|ui| {
                        ui.monospace(&r.pattern);
                    });
                    row.col(|ui| {
                        ui.label(if r.enabled { "Enabled" } else { "Disabled" });
                    });
                });
            });
        ui.separator();
        ui.strong("Evaluate a target without sending traffic");
        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut self.scope_target)
                    .hint_text("https://example.com/path")
                    .desired_width(450.0),
            );
            if ui
                .add_enabled(self.can_act(), egui::Button::new("Check scope"))
                .clicked()
            {
                self.action(Action::EvaluateScope {
                    target: self.scope_target.clone(),
                });
            }
        });
        self.output_panel(ui);
    }
    fn recon(&mut self, ui: &mut egui::Ui) {
        Self::heading(ui,"Recon & jobs","Resolve an in-scope hostname and inspect the scheduler. No external worker launch or port scan.");
        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut self.scope_target)
                    .hint_text("https://authorized.example")
                    .desired_width(400.0),
            );
            if ui
                .add_enabled(
                    self.can_act() && !self.scope_target.is_empty(),
                    egui::Button::new("Resolve hostname"),
                )
                .clicked()
            {
                self.action(Action::ResolveHost {
                    target: self.scope_target.clone(),
                });
            }
        });
        self.output_panel(ui);
        if self.data.jobs.is_empty() {
            Self::empty(ui,"No jobs for this project. Worker execution controls are not connected in this release.");
        }
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::remainder())
            .column(Column::exact(120.0))
            .column(Column::exact(100.0))
            .column(Column::remainder())
            .header(26.0, |mut h| {
                for s in ["TARGET", "STATUS", "PROGRESS", "CURRENT STEP"] {
                    h.col(|ui| {
                        ui.strong(s);
                    });
                }
            })
            .body(|body| {
                body.rows(28.0, self.data.jobs.len(), |mut row| {
                    let j = &self.data.jobs[row.index()];
                    row.col(|ui| {
                        ui.monospace(&j.target);
                    });
                    row.col(|ui| {
                        ui.label(format!("{:?}", j.status));
                    });
                    row.col(|ui| {
                        ui.monospace(format!("{:.0}%", j.progress));
                    });
                    row.col(|ui| {
                        ui.label(&j.current_step);
                    });
                });
            });
    }
    fn traffic(&mut self, ui: &mut egui::Ui) {
        Self::heading(
            ui,
            "HTTP history",
            "Newest 500 retained exchanges · session-wide · no proxy listener implied.",
        );
        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut self.traffic_filter)
                    .hint_text("Filter URL, method or status")
                    .desired_width(400.0),
            );
            ui.label(format!(
                "{} retained / {} evicted",
                self.data.total_traffic, self.data.evicted
            ));
        });
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.busy && self.data.total_traffic > 0,
                    egui::Button::new("Clear history…"),
                )
                .clicked()
            {
                self.clear_confirm = true;
            }
            if self.clear_confirm {
                ui.colored_label(AMBER, "Remove all session exchanges?");
                if ui.button("Confirm clear").clicked() {
                    self.clear_confirm = false;
                    self.selected_traffic = None;
                    self.action(Action::ClearTraffic);
                }
                if ui.button("Cancel").clicked() {
                    self.clear_confirm = false;
                }
            }
        });
        let query = self.traffic_filter.to_lowercase();
        let rows: Vec<_> = self
            .data
            .traffic
            .iter()
            .filter(|e| {
                format!(
                    "{} {} {}",
                    e.request.method,
                    e.request.url,
                    e.response.as_ref().map(|r| r.status_code).unwrap_or(0)
                )
                .to_lowercase()
                .contains(&query)
            })
            .collect();
        let mut selected = self.selected_traffic;
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .max_scroll_height(260.0)
            .column(Column::exact(65.0))
            .column(Column::exact(60.0))
            .column(Column::remainder())
            .column(Column::exact(80.0))
            .column(Column::exact(85.0))
            .header(26.0, |mut h| {
                for s in ["METHOD", "STATUS", "URL", "TIME", "BYTES"] {
                    h.col(|ui| {
                        ui.strong(s);
                    });
                }
            })
            .body(|body| {
                body.rows(
                    if self.compact { 26.0 } else { 34.0 },
                    rows.len(),
                    |mut row| {
                        let e = rows[row.index()];
                        row.col(|ui| {
                            ui.monospace(&e.request.method);
                        });
                        row.col(|ui| {
                            let status = e.response.as_ref().map(|r| r.status_code).unwrap_or(0);
                            ui.colored_label(
                                if status >= 400 { AMBER } else { GREEN },
                                status.to_string(),
                            );
                        });
                        row.col(|ui| {
                            if ui
                                .selectable_label(
                                    selected == Some(e.id),
                                    RichText::new(&e.request.url).monospace(),
                                )
                                .clicked()
                            {
                                selected = Some(e.id);
                            }
                        });
                        row.col(|ui| {
                            ui.monospace(
                                e.response
                                    .as_ref()
                                    .map(|r| format!("{} ms", r.duration_ms))
                                    .unwrap_or_default(),
                            );
                        });
                        row.col(|ui| {
                            ui.monospace(
                                e.response
                                    .as_ref()
                                    .map(|r| r.size_bytes.to_string())
                                    .unwrap_or_default(),
                            );
                        });
                    },
                );
            });
        self.selected_traffic = selected;
        if let Some(entry) = self
            .data
            .traffic
            .iter()
            .find(|e| Some(e.id) == selected)
            .cloned()
        {
            ui.separator();
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.response_tab, false, "Request");
                ui.selectable_value(&mut self.response_tab, true, "Response");
                if ui.button("Open in composer").clicked() {
                    self.url = entry.request.url.clone();
                    self.method = entry.request.method.clone();
                    self.headers =
                        serde_json::to_string_pretty(&entry.request.headers).unwrap_or_default();
                    self.body = entry.request.body.clone().unwrap_or_default();
                    self.view = View::Repeater;
                }
            });
            let mut text = if self.response_tab {
                serde_json::to_string_pretty(&entry.response)
            } else {
                serde_json::to_string_pretty(&entry.request)
            }
            .unwrap_or_default();
            egui::ScrollArea::both()
                .id_salt("traffic-detail")
                .max_height(350.0)
                .show(ui, |ui| {
                    ui.add(
                        TextEdit::multiline(&mut text)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .interactive(false),
                    );
                });
        } else {
            Self::empty(ui,"Select a captured exchange to inspect request and response. Use the composer to send a scoped request.");
        }
    }
    fn composer(&mut self, ui: &mut egui::Ui) {
        Self::heading(ui,"Request composer / repeater","Manual replay through the shared scope-checked HTTP client. Redirects are returned, not followed.");
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt("method")
                .selected_text(&self.method)
                .show_ui(ui, |ui| {
                    for m in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
                        ui.selectable_value(&mut self.method, m.into(), m);
                    }
                });
            ui.add(
                TextEdit::singleline(&mut self.url)
                    .hint_text("https://authorized.example/path")
                    .desired_width(ui.available_width()),
            );
        });
        ui.label("Headers (JSON string map)");
        ui.add(
            TextEdit::multiline(&mut self.headers)
                .font(egui::TextStyle::Monospace)
                .desired_rows(4)
                .desired_width(f32::INFINITY),
        );
        ui.label("Request body");
        ui.add(
            TextEdit::multiline(&mut self.body)
                .font(egui::TextStyle::Monospace)
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
        ui.colored_label(
            AMBER,
            "Send performs a real HTTP request. Non-GET methods may change data on the target.",
        );
        if ui
            .add_enabled(
                self.can_act() && !self.url.trim().is_empty(),
                egui::Button::new("Send request").fill(Color32::from_rgb(20, 83, 98)),
            )
            .clicked()
        {
            self.action(Action::SendRequest {
                url: self.url.trim().into(),
                method: self.method.clone(),
                headers: self.headers.clone(),
                body: self.body.clone(),
            });
        }
        self.output_panel(ui);
    }
    fn sql(&mut self, ui: &mut egui::Ui) {
        Self::heading(ui,"SQL research","Offline evidence review and dialect reference. HTTP responses cannot prove a database or supported SQL clauses.");
        ui.colored_label(AMBER,"Active SQL injection/timing probes are not connected. Signatures are hints, not verified DBMS identification.");
        ui.add(
            TextEdit::multiline(&mut self.sql_input)
                .hint_text("Paste a captured database error or diagnostic text")
                .desired_rows(5)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );
        if ui.button("Review evidence locally").clicked() {
            if self.sql_input.len() > 256 * 1024 {
                self.error = Some("Limit evidence input to 256 KiB.".into());
            } else {
                let result = bugtools_sql::detection::analyze_error_body(&self.sql_input);
                self.sql_result = if result.signals.is_empty() {
                    "Unknown: no matching signatures. Absence of an error does not identify the DBMS.".into()
                } else {
                    result
                        .signals
                        .iter()
                        .map(|s| {
                            format!(
                                "{}: {}\nMatched text: {}\n",
                                s.dbms.label(),
                                s.label,
                                s.needle
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                };
            }
        }
        if !self.sql_result.is_empty() {
            ui.label(RichText::new(&self.sql_result).monospace());
        }
        ui.separator();
        ui.strong("Dialect syntax reference · catalog data, not target verification");
        ui.add(
            TextEdit::singleline(&mut self.sql_filter)
                .hint_text("Filter clause or syntax")
                .desired_width(400.0),
        );
        let query = self.sql_filter.to_lowercase();
        egui::ScrollArea::vertical()
            .id_salt("sql-catalog")
            .max_height(360.0)
            .show(ui, |ui| {
                for clause in bugtools_sql::clause_map::clause_map() {
                    if !format!(
                        "{:?} {}",
                        clause.clause,
                        clause
                            .variants
                            .iter()
                            .map(|v| v.syntax)
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                    .to_lowercase()
                    .contains(&query)
                    {
                        continue;
                    }
                    egui::CollapsingHeader::new(format!(
                        "{:?} · {} variants",
                        clause.clause,
                        clause.variants.len()
                    ))
                    .show(ui, |ui| {
                        for variant in &clause.variants {
                            ui.monospace(variant.syntax);
                            ui.label(
                                RichText::new(format!(
                                    "Catalog lists: {}",
                                    variant
                                        .accepted_by
                                        .iter()
                                        .map(|d| d.label())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ))
                                .color(MUTED),
                            );
                            if let Some(note) = variant.notes {
                                ui.small(note);
                            }
                            ui.separator();
                        }
                    });
                }
            });
    }
    fn findings(&mut self, ui: &mut egui::Ui) {
        Self::heading(ui,"Findings","Record analyst-reviewed observations. New findings are candidates, not automatically verified vulnerabilities.");
        egui::CollapsingHeader::new("Record a finding")
            .default_open(self.data.findings.is_empty())
            .show(ui, |ui| {
                ui.label("Title");
                ui.add(TextEdit::singleline(&mut self.finding_title).desired_width(f32::INFINITY));
                ui.horizontal(|ui| {
                    ui.label("Severity");
                    egui::ComboBox::from_id_salt("severity")
                        .selected_text(&self.finding_severity)
                        .show_ui(ui, |ui| {
                            for s in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] {
                                ui.selectable_value(&mut self.finding_severity, s.into(), s);
                            }
                        });
                    ui.label("Target");
                    ui.text_edit_singleline(&mut self.finding_target);
                });
                ui.label("Evidence / notes (avoid credentials)");
                ui.add(
                    TextEdit::multiline(&mut self.finding_notes)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY),
                );
                if ui
                    .add_enabled(
                        self.can_act() && !self.finding_title.trim().is_empty(),
                        egui::Button::new("Save candidate finding"),
                    )
                    .clicked()
                {
                    self.action(Action::CreateFinding {
                        title: self.finding_title.clone(),
                        target: self.finding_target.clone(),
                        notes: self.finding_notes.clone(),
                        severity: self.finding_severity.clone(),
                    });
                }
            });
        ui.add(
            TextEdit::singleline(&mut self.finding_filter)
                .hint_text("Filter findings")
                .desired_width(360.0),
        );
        let q = self.finding_filter.to_lowercase();
        let findings: Vec<_> = self
            .data
            .findings
            .iter()
            .filter(|f| {
                format!("{} {}", f.title, f.target)
                    .to_lowercase()
                    .contains(&q)
            })
            .collect();
        TableBuilder::new(ui)
            .striped(true)
            .max_scroll_height(250.0)
            .column(Column::exact(85.0))
            .column(Column::remainder())
            .column(Column::exact(130.0))
            .header(26.0, |mut h| {
                for s in ["SEVERITY", "TITLE", "STATE"] {
                    h.col(|ui| {
                        ui.strong(s);
                    });
                }
            })
            .body(|body| {
                body.rows(28.0, findings.len(), |mut row| {
                    let f = findings[row.index()];
                    row.col(|ui| {
                        ui.monospace(format!("{:?}", f.severity));
                    });
                    row.col(|ui| {
                        if ui
                            .selectable_label(self.selected_finding == Some(f.id), &f.title)
                            .clicked()
                        {
                            self.selected_finding = Some(f.id);
                        }
                    });
                    row.col(|ui| {
                        ui.label(format!("{:?}", f.status));
                    });
                });
            });
        if let Some(f) = self
            .data
            .findings
            .iter()
            .find(|f| Some(f.id) == self.selected_finding)
        {
            ui.separator();
            ui.strong(&f.title);
            ui.monospace(&f.target);
            ui.label(f.notes.as_deref().unwrap_or("No notes"));
        }
    }
    fn reports(&mut self, ui: &mut egui::Ui) {
        Self::heading(ui,"Reports","Export the active project's findings to a new Markdown file. Existing files are never overwritten.");
        ui.label(format!(
            "Project: {} · {} findings",
            self.active_name(),
            self.data.findings.len()
        ));
        ui.colored_label(AMBER,"Review analyst notes for secrets before sharing. Raw traffic and authorization headers are excluded.");
        ui.label("Destination path on this computer");
        ui.add(TextEdit::singleline(&mut self.export_path).desired_width(f32::INFINITY));
        if ui
            .add_enabled(
                self.can_act() && !self.export_path.trim().is_empty(),
                egui::Button::new("Export Markdown report"),
            )
            .clicked()
        {
            self.action(Action::ExportReport {
                path: self.export_path.clone(),
            });
        }
        self.output_panel(ui);
    }
    fn settings(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        Self::heading(ui,"Settings & diagnostics","Appearance settings apply immediately. Backend limits below are informational, not disconnected controls.");
        if ui
            .checkbox(&mut self.compact, "Compact table density")
            .changed()
        {
            configure(ctx, self.compact);
        }
        ui.checkbox(
            &mut self.auto_refresh,
            "Refresh local snapshots every 3 seconds (no network scan)",
        );
        ui.separator();
        ui.strong("Backend");
        ui.monospace(format!("Database: {}", self.db_path.display()));
        ui.label("HTTP response cap: 2 MiB · request command timeout: 30 s · automatic redirects: disabled");
        ui.label("Scope: explicit domain inclusion required · traffic storage: session memory");
        ui.separator();
        ui.strong("Not connected in this GUI release");
        ui.label("External recon worker launch/cancellation, active SQL probes, automated fuzz runs, proxy interception and editable network settings.");
        ui.label("These are not represented by simulated success states or invented telemetry.");
    }
}
impl eframe::App for Workstation {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive();
        if self.auto_refresh
            && self.ready
            && !self.busy
            && self.last_refresh.elapsed() > Duration::from_secs(3)
        {
            self.action(Action::Refresh);
        }
        if self.auto_refresh {
            ctx.request_repaint_after(Duration::from_secs(1));
        }
        egui::TopBottomPanel::top("toolbar")
            .exact_height(52.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.strong(RichText::new("BUGTOOLS").color(CYAN));
                    ui.separator();
                    let mut choose = None;
                    egui::ComboBox::from_id_salt("active-project")
                        .selected_text(self.active_name())
                        .width(230.0)
                        .show_ui(ui, |ui| {
                            for p in &self.data.projects {
                                if ui
                                    .selectable_label(
                                        Some(p.id) == self.data.active_project,
                                        &p.name,
                                    )
                                    .clicked()
                                    && !self.busy
                                {
                                    choose = Some(p.id);
                                }
                            }
                        });
                    if let Some(id) = choose {
                        self.action(Action::SelectProject { id });
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .add_enabled(!self.busy, egui::Button::new("Refresh"))
                            .clicked()
                        {
                            self.action(Action::Refresh);
                        }
                        ui.label(
                            RichText::new(if self.busy {
                                "WORKING"
                            } else if self.ready {
                                "LOCAL / READY"
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
                    ui.separator();
                    ui.label(format!(
                        "{} findings  |  {} retained exchanges",
                        self.data.findings.len(),
                        self.data.total_traffic
                    ));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new("RUST + EGUI   /   SQLite")
                                .small()
                                .color(MUTED),
                        );
                    });
                });
            });
        egui::SidePanel::left("navigation")
            .exact_width(200.0)
            .resizable(false)
            .show(ctx, |ui| {
                ui.add_space(20.0);
                ui.label(RichText::new("RESEARCH WORKSTATION").small().color(MUTED));
                ui.add_space(16.0);
                for (i, view) in View::ALL.into_iter().enumerate() {
                    if ui
                        .add_sized(
                            [184.0, 34.0],
                            egui::Button::new(format!("{:02}   {}", i + 1, view.label()))
                                .selected(self.view == view),
                        )
                        .clicked()
                    {
                        self.view = view;
                    }
                }
                ui.add_space(24.0);
                ui.colored_label(MUTED, "Evidence before conclusions.");
            });
        egui::CentralPanel::default().show(ctx, |ui| {
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
            if self.data.active_project.is_none() && self.view != View::Projects {
                ui.colored_label(
                    AMBER,
                    "Select or create a project to enable project actions.",
                );
            }
            egui::ScrollArea::vertical()
                .id_salt(("page", format!("{:?}", self.view)))
                .auto_shrink([false, false])
                .show(ui, |ui| match self.view {
                    View::Dashboard => self.overview(ui),
                    View::Projects => self.projects(ui),
                    View::Scope => self.scope(ui),
                    View::Recon => self.recon(ui),
                    View::Traffic => self.traffic(ui),
                    View::Repeater => self.composer(ui),
                    View::Sql => self.sql(ui),
                    View::Findings => self.findings(ui),
                    View::Reports => self.reports(ui),
                    View::Settings => self.settings(ui, ctx),
                });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stable_style_has_no_motion_or_expansion() {
        let ctx = egui::Context::default();
        configure(&ctx, true);
        let s = ctx.style();
        assert_eq!(s.animation_time, 0.0);
        assert_eq!(s.visuals.widgets.hovered.expansion, 0.0);
        assert_eq!(s.visuals.widgets.active.expansion, 0.0);
    }
    #[test]
    fn navigation_labels_are_unique() {
        let mut labels = std::collections::HashSet::new();
        for view in View::ALL {
            assert!(labels.insert(view.label()));
        }
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;
    #[test]
    fn every_page_lays_out_at_minimum_and_desktop_size() {
        let ctx = egui::Context::default();
        let mut app = Workstation::with_context(&ctx, PathBuf::from(":memory:"));
        for width in [760.0, 1180.0] {
            for view in View::ALL {
                app.view = view;
                let raw = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(width, 800.0),
                    )),
                    ..Default::default()
                };
                let result = ctx.run(raw, |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| match view {
                        View::Dashboard => app.overview(ui),
                        View::Projects => app.projects(ui),
                        View::Scope => app.scope(ui),
                        View::Recon => app.recon(ui),
                        View::Traffic => app.traffic(ui),
                        View::Repeater => app.composer(ui),
                        View::Sql => app.sql(ui),
                        View::Findings => app.findings(ui),
                        View::Reports => app.reports(ui),
                        View::Settings => app.settings(ui, ctx),
                    });
                });
                assert!(
                    !result.shapes.is_empty(),
                    "page {view:?} produced no shapes"
                );
            }
        }
    }
}
