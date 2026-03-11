use eframe::egui::{self, RichText};
use super::app::BitmessageApp;
use super::theme;
use super::theme::icon;
use crate::crypto::address::BitmessageAddress;

pub fn render_identities(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    // Header
    theme::header_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::IDENTITY).size(18.0).color(theme::ACCENT));
            ui.label(RichText::new("Identities").size(18.0).strong());
            ui.add_space(16.0);
            ui.label(
                RichText::new(format!("{} addresses", app.identities.len()))
                    .color(theme::TEXT_DIM)
                    .size(12.0),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(theme::accent_button(&theme::icon_text(icon::ADD, "New Identity")))
                    .clicked()
                {
                    app.show_create_identity = true;
                    app.new_identity_label.clear();
                }

                // Import identities from JSON file
                if ui
                    .add(theme::subtle_button(&theme::icon_text(icon::ADD, "Import")))
                    .clicked()
                {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("JSON", &["json"])
                        .pick_file()
                    {
                        match std::fs::read_to_string(&path) {
                            Ok(json_str) => {
                                match serde_json::from_str::<Vec<crate::storage::ExportedIdentity>>(&json_str) {
                                    Ok(exported) => {
                                        let import_result = {
                                            if let Ok(db) = app.db.lock() {
                                                Some(db.import_identities(&exported))
                                            } else {
                                                None
                                            }
                                        };
                                        if let Some(result) = import_result {
                                            match result {
                                                Ok(count) => {
                                                    app.notifications.push((
                                                        format!("Imported {} identities", count),
                                                        std::time::Instant::now(),
                                                    ));
                                                    app.refresh_data();
                                                }
                                                Err(e) => {
                                                    app.notifications.push((
                                                        format!("Import error: {e}"),
                                                        std::time::Instant::now(),
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        app.notifications.push((
                                            format!("Invalid JSON: {e}"),
                                            std::time::Instant::now(),
                                        ));
                                    }
                                }
                            }
                            Err(e) => {
                                app.notifications.push((
                                    format!("Failed to read file: {e}"),
                                    std::time::Instant::now(),
                                ));
                            }
                        }
                    }
                }

                // Export all identities to JSON file
                if ui
                    .add(theme::subtle_button(&theme::icon_text(icon::SAVE, "Export All")))
                    .clicked()
                {
                    let export_result = {
                        if let Ok(db) = app.db.lock() {
                            Some(db.export_identities())
                        } else {
                            None
                        }
                    };
                    if let Some(result) = export_result {
                        match result {
                            Ok(exported) => {
                                match serde_json::to_string_pretty(&exported) {
                                    Ok(json_str) => {
                                        if let Some(path) = rfd::FileDialog::new()
                                            .set_file_name("bitmessage_identities.json")
                                            .add_filter("JSON", &["json"])
                                            .save_file()
                                        {
                                            match std::fs::write(&path, json_str) {
                                                Ok(()) => {
                                                    app.notifications.push((
                                                        format!("Exported {} identities", exported.len()),
                                                        std::time::Instant::now(),
                                                    ));
                                                }
                                                Err(e) => {
                                                    app.notifications.push((
                                                        format!("Failed to write file: {e}"),
                                                        std::time::Instant::now(),
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        app.notifications.push((
                                            format!("Serialization error: {e}"),
                                            std::time::Instant::now(),
                                        ));
                                    }
                                }
                            }
                            Err(e) => {
                                app.notifications.push((
                                    format!("Export error: {e}"),
                                    std::time::Instant::now(),
                                ));
                            }
                        }
                    }
                }
            });
        });
    });

    // Create identity dialog
    if app.show_create_identity {
        render_create_identity_dialog(app, ui);
    }

    // Identity list
    if app.identities.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.label(
                RichText::new("No identities")
                    .color(theme::TEXT_DIM)
                    .size(16.0),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new("Create an identity to start sending and receiving messages")
                    .color(theme::TEXT_DIM)
                    .size(12.0),
            );
            ui.add_space(16.0);
            if ui
                .add(theme::accent_button(&theme::icon_text(icon::ADD, "Create Your First Identity")))
                .clicked()
            {
                app.show_create_identity = true;
                app.new_identity_label.clear();
            }
        });
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.add_space(8.0);
            let identities = app.identities.clone();
            for identity in &identities {
                render_identity_card(app, ui, identity);
            }
        });
}

fn render_identity_card(
    app: &mut BitmessageApp,
    ui: &mut egui::Ui,
    identity: &crate::storage::StoredIdentity,
) {
    let id = identity.id;
    let enabled = identity.enabled;

    theme::card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width() - 32.0);
        ui.horizontal(|ui| {
            // Key icon
            let (rect, _) = ui.allocate_exact_size(egui::vec2(44.0, 44.0), egui::Sense::hover());
            let color = if enabled {
                theme::ACCENT
            } else {
                theme::TEXT_DIM
            };
            ui.painter()
                .rect_filled(rect, egui::Rounding::same(10.0), color.linear_multiply(0.3));
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                icon::KEY,
                egui::FontId::proportional(18.0),
                color,
            );

            ui.add_space(8.0);

            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&identity.label).strong().size(14.0));
                    if !enabled {
                        ui.label(
                            RichText::new("(disabled)")
                                .color(theme::TEXT_DIM)
                                .size(11.0),
                        );
                    }
                });

                ui.label(
                    RichText::new(&identity.address)
                        .color(theme::ACCENT)
                        .size(11.0),
                );

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "v{} stream {}",
                            identity.address_version, identity.stream_number
                        ))
                        .color(theme::TEXT_DIM)
                        .size(10.0),
                    );
                    ui.label(
                        RichText::new(format!(
                            "PoW: {}/{}",
                            identity.nonce_trials, identity.extra_bytes
                        ))
                        .color(theme::TEXT_DIM)
                        .size(10.0),
                    );
                    ui.label(
                        RichText::new(format!(
                            "Created: {}",
                            theme::format_time(identity.created_at)
                        ))
                        .color(theme::TEXT_DIM)
                        .size(10.0),
                    );
                });
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(theme::subtle_button(&theme::icon_text(icon::DELETE, "Delete"))).clicked() {
                    if let Ok(db) = app.db.lock() {
                        let _ = db.delete_identity(id);
                    }
                    app.refresh_data();
                }

                let toggle_label = if enabled {
                    theme::icon_text(icon::DELETE, "Disable")
                } else {
                    theme::icon_text(icon::CHECK, "Enable")
                };
                if ui.add(theme::subtle_button(&toggle_label)).clicked() {
                    if let Ok(db) = app.db.lock() {
                        let _ = db.toggle_identity(id, !enabled);
                    }
                    app.refresh_data();
                }

                // Export private key
                if ui.add(theme::subtle_button(&theme::icon_text(icon::KEY, "Export"))).clicked() {
                    let sk_hex = hex::encode(&identity.signing_key);
                    let ek_hex = hex::encode(&identity.encryption_key);
                    let export_str = format!("{}:{}", sk_hex, ek_hex);
                    ui.ctx().copy_text(export_str);
                    app.notifications.push((
                        "Private keys copied to clipboard".into(),
                        std::time::Instant::now(),
                    ));
                }

                // Copy address
                if ui.add(theme::subtle_button(&theme::icon_text(icon::COPY, "Copy"))).clicked() {
                    ui.ctx().copy_text(identity.address.clone());
                    app.notifications.push((
                        "Address copied to clipboard".into(),
                        std::time::Instant::now(),
                    ));
                }
            });
        });
    });

    ui.add_space(2.0);
}

fn render_create_identity_dialog(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    egui::Frame {
        fill: theme::BG_PANEL,
        inner_margin: egui::Margin::symmetric(20.0, 16.0),
        rounding: egui::Rounding::same(10.0),
        outer_margin: egui::Margin::symmetric(16.0, 8.0),
        stroke: egui::Stroke::new(1.0, theme::ACCENT_MUTED),
        ..Default::default()
    }
    .show(ui, |ui| {
        ui.label(RichText::new(theme::icon_text(icon::IDENTITY, "Create New Identity")).size(14.0).strong());
        ui.add_space(4.0);
        ui.label(
            RichText::new(
                "Generate a new Bitmessage address. This creates a random v4 address on stream 1.",
            )
            .color(theme::TEXT_DIM)
            .size(11.0),
        );
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label(RichText::new("Label:").color(theme::TEXT_DIM).size(13.0));
            ui.add_space(8.0);
            ui.add(
                egui::TextEdit::singleline(&mut app.new_identity_label)
                    .hint_text("My identity")
                    .desired_width(300.0),
            );
        });

        ui.add_space(8.0);

        ui.horizontal(|ui| {
            let can_create = !app.new_identity_label.is_empty();
            ui.add_enabled_ui(can_create, |ui| {
                if ui.add(theme::accent_button(&theme::icon_text(icon::KEY, "Generate"))).clicked() {
                    create_identity(app);
                }
            });
            if ui.add(theme::subtle_button("Cancel")).clicked() {
                app.show_create_identity = false;
            }
        });
    });
}

fn create_identity(app: &mut BitmessageApp) {
    let label = app.new_identity_label.clone();

    match BitmessageAddress::generate_random(&label) {
        Ok((addr, keypair)) => {
            let now = chrono::Utc::now().timestamp();
            let identity = crate::storage::StoredIdentity {
                id: 0,
                label,
                address: addr.encoded.clone(),
                signing_key: keypair.signing_secret.clone(),
                encryption_key: keypair.encryption_secret.clone(),
                pub_signing_key: keypair.public_signing_key.to_vec(),
                pub_encryption_key: keypair.public_encryption_key.to_vec(),
                address_version: addr.version as i64,
                stream_number: addr.stream as i64,
                enabled: true,
                nonce_trials: 1000,
                extra_bytes: 1000,
                created_at: now,
            };

            if let Ok(db) = app.db.lock() {
                let _ = db.insert_identity(&identity);
            }

            app.notifications.push((
                format!("Created identity: {}", addr.encoded),
                std::time::Instant::now(),
            ));
            app.refresh_data();
            app.show_create_identity = false;
        }
        Err(e) => {
            app.notifications.push((
                format!("Failed to create identity: {e}"),
                std::time::Instant::now(),
            ));
        }
    }
}
