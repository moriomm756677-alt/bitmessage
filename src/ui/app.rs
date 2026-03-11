use eframe::egui::{self, Color32, RichText, TextureHandle};
use std::sync::{mpsc, Arc, Mutex};

use crate::network::{NetworkCommand, NetworkEvent};
use crate::storage::*;
use super::theme;
use super::theme::icon;
use super::tray;

#[derive(Debug, Clone, PartialEq)]
pub enum View {
    Inbox,
    Sent,
    Trash,
    MessageDetail(i64),
    Compose,
    Contacts,
    Channels,
    Subscriptions,
    Identities,
    Blacklist,
    Settings,
    NetworkStatus,
}

pub struct AttachedFile {
    pub filename: String,
    pub mime_type: String,
    pub data: Vec<u8>,
}

pub struct ComposeState {
    pub to: String,
    pub from_idx: usize,
    pub subject: String,
    pub body: String,
    pub is_broadcast: bool,
    /// Cursor range in body (char indices): (start, end)
    pub body_cursor: Option<(usize, usize)>,
    /// Visual mode: true = rendered BBCode, false = source editor
    pub visual_mode: bool,
    /// Attached file
    pub attached_file: Option<AttachedFile>,
}

impl Default for ComposeState {
    fn default() -> Self {
        Self {
            to: String::new(),
            from_idx: 0,
            subject: String::new(),
            body: String::new(),
            is_broadcast: false,
            body_cursor: None,
            visual_mode: false,
            attached_file: None,
        }
    }
}

pub struct BitmessageApp {
    // Data
    pub db: Arc<Mutex<Database>>,
    pub cmd_tx: mpsc::Sender<NetworkCommand>,
    pub event_rx: mpsc::Receiver<NetworkEvent>,
    pub _runtime: Arc<tokio::runtime::Runtime>,

    // Cached state
    pub identities: Vec<StoredIdentity>,
    pub contacts: Vec<StoredContact>,
    pub inbox: Vec<StoredMessage>,
    pub sent: Vec<StoredMessage>,
    pub trash: Vec<StoredMessage>,
    pub channels: Vec<StoredChannel>,
    pub subscriptions: Vec<StoredSubscription>,
    pub blacklist: Vec<crate::storage::BlacklistEntry>,
    pub unread_inbox: i64,

    // UI state
    pub current_view: View,
    pub compose: ComposeState,
    pub search_query: String,
    pub selected_msg_id: Option<i64>,
    pub selected_messages: std::collections::HashSet<i64>,

    // Pagination
    pub page_offset: i64,
    pub page_size: i64,
    pub total_inbox: i64,
    pub total_sent: i64,
    pub total_trash: i64,

    // Dialogs
    pub show_add_contact: bool,
    pub new_contact_label: String,
    pub new_contact_address: String,
    pub show_create_identity: bool,
    pub new_identity_label: String,
    pub show_join_channel: bool,
    pub new_channel_passphrase: String,
    pub show_add_subscription: bool,
    pub new_sub_label: String,
    pub new_sub_address: String,
    pub show_add_blacklist: bool,
    pub new_blacklist_label: String,
    pub new_blacklist_address: String,

    // Network
    pub peer_count: usize,
    pub status_message: String,
    pub notifications: Vec<(String, std::time::Instant)>,
    pub objects_received: u64,
    pub objects_processed: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub inventory_count: i64,

    // Tor
    pub tor_connected: bool,
    pub tor_bootstrap_pct: u8,
    pub tor_status_message: String,

    // Refresh
    last_refresh: std::time::Instant,

    // System tray
    pub tray: Option<tray::AppTray>,
    pub minimized_to_tray: bool,

    // Logo
    pub logo_texture: Option<TextureHandle>,
    pub tor_icon_texture: Option<TextureHandle>,

    // Error dialog
    pub error_message: Option<(String, std::time::Instant)>,

    // Settings (loaded from DB)
    pub setting_max_connections: String,
    pub setting_nonce_trials: String,
    pub setting_extra_bytes: String,
    pub setting_default_ttl_days: String,

    // Security
    pub password_input: String,
    pub show_password_dialog: bool,
    pub keys_encrypted: bool,
}

impl BitmessageApp {
    pub fn new(
        db: Arc<Mutex<Database>>,
        cmd_tx: mpsc::Sender<NetworkCommand>,
        event_rx: mpsc::Receiver<NetworkEvent>,
        runtime: Arc<tokio::runtime::Runtime>,
        tray: Option<tray::AppTray>,
    ) -> Self {
        let mut app = Self {
            db,
            cmd_tx,
            event_rx,
            _runtime: runtime,
            identities: vec![],
            contacts: vec![],
            inbox: vec![],
            sent: vec![],
            trash: vec![],
            channels: vec![],
            subscriptions: vec![],
            blacklist: vec![],
            unread_inbox: 0,
            current_view: View::Inbox,
            compose: ComposeState::default(),
            search_query: String::new(),
            selected_msg_id: None,
            selected_messages: std::collections::HashSet::new(),
            page_offset: 0,
            page_size: 50,
            total_inbox: 0,
            total_sent: 0,
            total_trash: 0,
            show_add_contact: false,
            new_contact_label: String::new(),
            new_contact_address: String::new(),
            show_create_identity: false,
            new_identity_label: String::new(),
            show_join_channel: false,
            new_channel_passphrase: String::new(),
            show_add_subscription: false,
            new_sub_label: String::new(),
            new_sub_address: String::new(),
            show_add_blacklist: false,
            new_blacklist_label: String::new(),
            new_blacklist_address: String::new(),
            peer_count: 0,
            status_message: "Starting...".into(),
            notifications: vec![],
            objects_received: 0,
            objects_processed: 0,
            bytes_sent: 0,
            bytes_received: 0,
            inventory_count: 0,
            tor_connected: false,
            tor_bootstrap_pct: 0,
            tor_status_message: "Initializing Tor...".into(),
            last_refresh: std::time::Instant::now(),
            tray,
            minimized_to_tray: false,
            logo_texture: None,
            tor_icon_texture: None,
            error_message: None,
            setting_max_connections: "8".into(),
            setting_nonce_trials: "1000".into(),
            setting_extra_bytes: "1000".into(),
            setting_default_ttl_days: "4".into(),
            password_input: String::new(),
            show_password_dialog: false,
            keys_encrypted: false,
        };
        app.refresh_data();
        // Load persisted settings from DB
        if let Ok(db) = app.db.lock() {
            app.setting_max_connections = db.get_setting("max_connections").unwrap_or_else(|| "8".into());
            app.setting_nonce_trials = db.get_setting("nonce_trials").unwrap_or_else(|| "1000".into());
            app.setting_extra_bytes = db.get_setting("extra_bytes").unwrap_or_else(|| "1000".into());
            app.setting_default_ttl_days = db.get_setting("default_ttl_days").unwrap_or_else(|| "4".into());
            app.keys_encrypted = db.are_keys_encrypted();
        }
        app
    }

    pub fn refresh_data(&mut self) {
        if let Ok(db) = self.db.lock() {
            self.identities = db.get_identities().unwrap_or_default();
            self.contacts = db.get_contacts().unwrap_or_default();
            self.inbox = db.get_messages_by_folder_paged("inbox", self.page_size, self.page_offset).unwrap_or_default();
            self.sent = db.get_messages_by_folder_paged("sent", self.page_size, self.page_offset).unwrap_or_default();
            self.trash = db.get_messages_by_folder_paged("trash", self.page_size, self.page_offset).unwrap_or_default();
            self.total_inbox = db.count_messages_by_folder("inbox").unwrap_or(0);
            self.total_sent = db.count_messages_by_folder("sent").unwrap_or(0);
            self.total_trash = db.count_messages_by_folder("trash").unwrap_or(0);
            self.channels = db.get_channels().unwrap_or_default();
            self.subscriptions = db.get_subscriptions().unwrap_or_default();
            self.blacklist = db.get_blacklist().unwrap_or_default();
            self.unread_inbox = db.unread_count("inbox").unwrap_or(0);
            self.inventory_count = db.inventory_count().unwrap_or(0);
        }
        self.last_refresh = std::time::Instant::now();
    }

    fn poll_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                NetworkEvent::PeerCountChanged(n) => self.peer_count = n,
                NetworkEvent::StatusUpdate(msg) => self.status_message = msg,
                NetworkEvent::PeerConnected(addr) => {
                    self.notifications
                        .push((format!("{} Connected: {addr}", icon::CHECK), std::time::Instant::now()));
                }
                NetworkEvent::PeerDisconnected(addr) => {
                    self.notifications
                        .push((format!("{} Disconnected: {addr}", icon::DELETE), std::time::Instant::now()));
                }
                NetworkEvent::MessageReceived { from, subject, .. } => {
                    self.notifications.push((
                        format!("{} New: {from} - {subject}", icon::INBOX),
                        std::time::Instant::now(),
                    ));
                    self.refresh_data();
                }
                NetworkEvent::Error(e) => {
                    self.error_message = Some((e.clone(), std::time::Instant::now()));
                    self.notifications
                        .push((format!("{} {e}", icon::DELETE), std::time::Instant::now()));
                }
                NetworkEvent::BroadcastReceived { from, subject, .. } => {
                    self.notifications.push((
                        format!("{} Broadcast: {from} - {subject}", icon::SUBS),
                        std::time::Instant::now(),
                    ));
                    self.refresh_data();
                }
                NetworkEvent::PubkeyReceived { address } => {
                    self.notifications.push((
                        format!("{} Pubkey received: {address}", icon::KEY),
                        std::time::Instant::now(),
                    ));
                }
                NetworkEvent::FileProgress { filename, chunks_done, total_chunks, .. } => {
                    self.notifications.push((
                        format!("{} File: {filename} ({chunks_done}/{total_chunks})", icon::CHECK),
                        std::time::Instant::now(),
                    ));
                    if chunks_done >= total_chunks {
                        self.refresh_data();
                    }
                }
                NetworkEvent::TorStatus { connected, bootstrap_pct, message } => {
                    self.tor_connected = connected;
                    self.tor_bootstrap_pct = bootstrap_pct;
                    self.tor_status_message = message;
                }
                NetworkEvent::StatsUpdate {
                    objects_received,
                    objects_processed,
                    bytes_sent,
                    bytes_received,
                    inventory_count,
                } => {
                    self.objects_received = objects_received;
                    self.objects_processed = objects_processed;
                    self.bytes_sent = bytes_sent;
                    self.bytes_received = bytes_received;
                    self.inventory_count = inventory_count;
                }
            }
        }
        self.notifications
            .retain(|(_, t)| t.elapsed() < std::time::Duration::from_secs(5));
    }

    fn render_sidebar(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            // Logo
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if let Some(tex) = &self.logo_texture {
                    let logo_size = egui::vec2(22.0, 22.0);
                    ui.image(egui::load::SizedTexture::new(tex.id(), logo_size));
                }
                ui.label(
                    RichText::new("Bitmessage")
                        .size(18.0)
                        .strong()
                        .color(theme::ACCENT),
                );
            });
            ui.add_space(10.0);

            // Compose button
            if ui
                .add(
                    theme::accent_button(&theme::icon_text(icon::COMPOSE, "New Message"))
                        .min_size(egui::vec2(ui.available_width(), 36.0)),
                )
                .clicked()
            {
                self.compose = ComposeState::default();
                self.current_view = View::Compose;
            }

            ui.add_space(4.0);

            // --- Messages ---
            theme::section_header(ui, "Messages");
            self.nav_item(ui, icon::INBOX, "Inbox", View::Inbox, Some(self.unread_inbox));
            self.nav_item(ui, icon::SENT, "Sent", View::Sent, None);
            self.nav_item(ui, icon::TRASH, "Trash", View::Trash, None);

            // --- People ---
            theme::section_header(ui, "People");
            self.nav_item(ui, icon::CONTACTS, "Contacts", View::Contacts, None);
            self.nav_item(ui, icon::SUBS, "Subscriptions", View::Subscriptions, None);
            self.nav_item(ui, icon::CHANNELS, "Channels", View::Channels, None);

            // --- System ---
            theme::section_header(ui, "System");
            self.nav_item(ui, icon::IDENTITY, "Identities", View::Identities, None);
            self.nav_item(ui, icon::LOCK, "Blacklist", View::Blacklist, None);
            self.nav_item(ui, icon::NETWORK, "Network", View::NetworkStatus, None);
            self.nav_item(ui, icon::SETTINGS, "Settings", View::Settings, None);

            // Spacer to push status to bottom
            let remaining = ui.available_height() - 36.0;
            if remaining > 0.0 {
                ui.add_space(remaining);
            }

            // Status bar
            ui.separator();
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 3.0;

                // Tor indicator with onion icon
                let tor_color = if self.tor_connected {
                    theme::SUCCESS
                } else if self.tor_bootstrap_pct > 0 {
                    theme::WARNING
                } else {
                    theme::ERROR
                };
                if let Some(tex) = &self.tor_icon_texture {
                    let icon_size = egui::vec2(14.0, 14.0);
                    let tint = if self.tor_connected {
                        Color32::WHITE
                    } else {
                        Color32::from_rgba_premultiplied(100, 100, 100, 180)
                    };
                    ui.add(
                        egui::Image::new(egui::load::SizedTexture::new(tex.id(), icon_size))
                            .tint(tint),
                    );
                }
                ui.label(RichText::new("Tor").color(tor_color).size(10.0));

                ui.label(RichText::new(" & ").color(theme::TEXT_DIM).size(10.0));

                // Peer status
                let dot_color = if self.peer_count > 0 {
                    theme::SUCCESS
                } else {
                    theme::TEXT_DIM
                };
                let peer_text = if self.peer_count > 0 {
                    format!("{} peers", self.peer_count)
                } else {
                    "0 peers".into()
                };
                ui.label(RichText::new(icon::DOT).color(dot_color).size(10.0));
                ui.label(RichText::new(peer_text).color(theme::TEXT_DIM).size(10.0));
            });
        });
    }

    fn nav_item(
        &mut self,
        ui: &mut egui::Ui,
        nav_icon: &str,
        label: &str,
        view: View,
        badge: Option<i64>,
    ) {
        let selected = self.current_view == view;
        let fill = if selected {
            theme::BG_SELECTED
        } else {
            Color32::TRANSPARENT
        };

        let frame = egui::Frame {
            fill,
            rounding: egui::Rounding::same(6.0),
            inner_margin: egui::Margin::symmetric(10.0, 5.0),
            ..Default::default()
        };

        let response = frame
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    let icon_color = if selected {
                        theme::ACCENT
                    } else {
                        theme::TEXT_DIM
                    };
                    ui.label(RichText::new(nav_icon).color(icon_color).size(13.0));

                    let text_color = if selected {
                        Color32::WHITE
                    } else {
                        theme::TEXT_SECONDARY
                    };
                    ui.label(RichText::new(label).color(text_color).size(13.0));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if let Some(count) = badge {
                            theme::unread_badge(ui, count);
                        }
                    });
                });
            })
            .response;

        if response.interact(egui::Sense::click()).clicked() {
            self.selected_messages.clear();
            self.page_offset = 0;
            self.current_view = view;
            self.refresh_data();
        }
    }

    fn render_notifications(&self, ctx: &egui::Context) {
        if self.notifications.is_empty() {
            return;
        }
        egui::Area::new(egui::Id::new("notifications"))
            .anchor(egui::Align2::RIGHT_TOP, egui::vec2(-16.0, 16.0))
            .show(ctx, |ui| {
                for (msg, _) in &self.notifications {
                    egui::Frame::default()
                        .fill(theme::BG_SURFACE)
                        .rounding(8.0)
                        .inner_margin(egui::Margin::symmetric(14.0, 10.0))
                        .stroke(egui::Stroke::new(1.0, theme::BORDER_LIGHT))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(msg)
                                    .color(theme::TEXT_PRIMARY)
                                    .size(12.0),
                            );
                        });
                    ui.add_space(4.0);
                }
            });
    }
}

impl eframe::App for BitmessageApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_events();

        // Load logo textures once
        if self.logo_texture.is_none() {
            let icon_data = include_bytes!("../logo_icon.png");
            if let Ok(img) = image::load_from_memory(icon_data) {
                let rgba = img.to_rgba8();
                let size = [rgba.width() as usize, rgba.height() as usize];
                let pixels = rgba.into_raw();
                let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);
                self.logo_texture = Some(ctx.load_texture(
                    "logo",
                    color_image,
                    egui::TextureOptions::LINEAR,
                ));
            }
        }
        if self.tor_icon_texture.is_none() {
            let tor_data = include_bytes!("../tor_icon.png");
            if let Ok(img) = image::load_from_memory(tor_data) {
                let rgba = img.to_rgba8();
                let size = [rgba.width() as usize, rgba.height() as usize];
                let pixels = rgba.into_raw();
                let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);
                self.tor_icon_texture = Some(ctx.load_texture(
                    "tor_icon",
                    color_image,
                    egui::TextureOptions::LINEAR,
                ));
            }
        }

        if self.last_refresh.elapsed() > std::time::Duration::from_secs(2) {
            self.refresh_data();
        }

        // Update tray icon state
        if let Some(ref mut t) = self.tray {
            t.update(self.unread_inbox, self.peer_count > 0);
        }

        // Handle tray events
        match tray::poll_tray_events() {
            tray::TrayAction::Show => {
                if self.minimized_to_tray {
                    self.minimized_to_tray = false;
                    // Restore window position and show
                    ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(
                        egui::pos2(100.0, 100.0),
                    ));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
            }
            tray::TrayAction::Quit => {
                // Real quit — bypass tray intercept
                self.tray = None;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            tray::TrayAction::None => {}
        }

        // Intercept window close → minimize to tray instead
        if ctx.input(|i| i.viewport().close_requested()) {
            if self.tray.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                self.minimized_to_tray = true;
            }
        }

        ctx.request_repaint_after(std::time::Duration::from_secs(1));

        // Sidebar
        egui::SidePanel::left("nav_panel")
            .exact_width(220.0)
            .frame(theme::sidebar_frame())
            .show(ctx, |ui| {
                self.render_sidebar(ui);
            });

        // Main content
        egui::CentralPanel::default()
            .frame(egui::Frame {
                fill: theme::BG_DARK,
                inner_margin: egui::Margin::same(0.0),
                ..Default::default()
            })
            .show(ctx, |ui| {
                // Error banner
                let mut dismiss_error = false;
                if let Some((ref msg, instant)) = self.error_message {
                    if instant.elapsed() < std::time::Duration::from_secs(10) {
                        egui::Frame {
                            fill: Color32::from_rgb(80, 20, 20),
                            inner_margin: egui::Margin::symmetric(16.0, 10.0),
                            rounding: egui::Rounding::same(6.0),
                            outer_margin: egui::Margin::symmetric(16.0, 4.0),
                            ..Default::default()
                        }
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(icon::DELETE).color(theme::ERROR).size(14.0));
                                ui.label(RichText::new(msg).color(theme::ERROR).size(13.0));
                                if ui.add(theme::subtle_button("Dismiss")).clicked() {
                                    dismiss_error = true;
                                }
                            });
                        });
                    } else {
                        dismiss_error = true;
                    }
                }
                if dismiss_error {
                    self.error_message = None;
                }

                let view = self.current_view.clone();
                match view {
                    View::Inbox => super::inbox::render_inbox(self, ui),
                    View::Sent => super::inbox::render_sent(self, ui),
                    View::Trash => super::inbox::render_trash(self, ui),
                    View::MessageDetail(id) => super::inbox::render_message_detail(self, ui, id),
                    View::Compose => super::compose::render_compose(self, ui),
                    View::Contacts => super::contacts::render_contacts(self, ui),
                    View::Channels => super::channels::render_channels(self, ui),
                    View::Subscriptions => super::channels::render_subscriptions(self, ui),
                    View::Identities => super::identities::render_identities(self, ui),
                    View::Blacklist => super::blacklist::render_blacklist(self, ui),
                    View::Settings => super::settings::render_settings(self, ui),
                    View::NetworkStatus => super::settings::render_network_status(self, ui),
                }
            });

        self.render_notifications(ctx);
    }
}
