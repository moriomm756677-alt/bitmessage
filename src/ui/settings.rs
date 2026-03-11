use eframe::egui::{self, RichText};
use super::app::BitmessageApp;
use super::theme;
use super::theme::icon;

pub fn render_settings(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    // Header
    theme::header_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::SETTINGS).size(18.0).color(theme::ACCENT));
            ui.label(RichText::new("Settings").size(18.0).strong());
        });
    });

    egui::ScrollArea::vertical()
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.add_space(16.0);

            // Network settings
            settings_section(ui, &theme::icon_text(icon::NETWORK, "Network"), |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Listen port:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(RichText::new("8444").size(13.0));
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Max connections:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut app.setting_max_connections)
                            .desired_width(60.0)
                            .font(egui::TextStyle::Body),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Protocol version:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(RichText::new("3").size(13.0));
                });
            });

            // Proof of Work settings
            settings_section(ui, &theme::icon_text(icon::STAR, "Proof of Work"), |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Default nonce trials per byte:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut app.setting_nonce_trials)
                            .desired_width(80.0)
                            .font(egui::TextStyle::Body),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Default extra bytes:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut app.setting_extra_bytes)
                            .desired_width(80.0)
                            .font(egui::TextStyle::Body),
                    );
                });
            });

            // Message settings
            settings_section(ui, &theme::icon_text(icon::INBOX, "Messages"), |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Default TTL (days):")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut app.setting_default_ttl_days)
                            .desired_width(60.0)
                            .font(egui::TextStyle::Body),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Default encoding:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(RichText::new("Simple (type 2)").size(13.0));
                });
            });

            // Save button
            ui.add_space(8.0);
            egui::Frame {
                fill: theme::BG_PANEL,
                inner_margin: egui::Margin::symmetric(20.0, 12.0),
                rounding: egui::Rounding::same(8.0),
                outer_margin: egui::Margin::symmetric(16.0, 4.0),
                stroke: egui::Stroke::new(0.5, theme::BORDER),
                ..Default::default()
            }
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                if ui.add(theme::accent_button(&theme::icon_text(icon::CHECK, "Save Settings"))).clicked() {
                    if let Ok(db) = app.db.lock() {
                        let _ = db.set_setting("max_connections", &app.setting_max_connections);
                        let _ = db.set_setting("nonce_trials", &app.setting_nonce_trials);
                        let _ = db.set_setting("extra_bytes", &app.setting_extra_bytes);
                        let _ = db.set_setting("default_ttl_days", &app.setting_default_ttl_days);
                    }
                    app.notifications.push((
                        format!("{} Settings saved", super::theme::icon::CHECK),
                        std::time::Instant::now(),
                    ));
                }
            });

            // Security
            settings_section(ui, &theme::icon_text(icon::LOCK, "Security"), |ui| {
                if app.keys_encrypted {
                    if app.session_key.is_some() {
                        ui.label(
                            RichText::new("Private keys are encrypted and unlocked")
                                .color(theme::SUCCESS)
                                .size(13.0),
                        );
                    } else {
                        ui.label(
                            RichText::new("Private keys are encrypted (locked)")
                                .color(theme::WARNING)
                                .size(13.0),
                        );
                    }
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Password:").color(theme::TEXT_DIM).size(13.0));
                        ui.add(egui::TextEdit::singleline(&mut app.password_input)
                            .password(true)
                            .hint_text("Enter password")
                            .desired_width(200.0));
                    });
                    ui.horizontal(|ui| {
                        // Unlock button (if not yet unlocked)
                        if app.session_key.is_none() {
                            if ui.add(theme::accent_button("Unlock")).clicked() {
                                if !app.password_input.is_empty() {
                                    let key = crate::storage::derive_key_from_password(&app.password_input);
                                    // Verify password by trying to decrypt first identity's raw key
                                    let valid = if let Ok(db) = app.db.lock() {
                                        // Read raw keys (no session key set yet, so no auto-decrypt)
                                        let raw_ok = db.get_identities().ok();
                                        if let Some(ids) = &raw_ok {
                                            if let Some(id) = ids.first() {
                                                if id.signing_key.len() > 32 {
                                                    crate::storage::simple_decrypt_pub(&key, &id.signing_key).is_ok()
                                                } else {
                                                    true
                                                }
                                            } else {
                                                true
                                            }
                                        } else {
                                            false
                                        }
                                    } else {
                                        false
                                    };
                                    if valid {
                                        app.session_key = Some(key);
                                        if let Ok(mut db) = app.db.lock() {
                                            db.set_session_key(Some(key));
                                        }
                                        app.notifications.push((
                                            format!("{} Keys unlocked", icon::CHECK),
                                            std::time::Instant::now(),
                                        ));
                                        app.refresh_data();
                                    } else {
                                        app.notifications.push((
                                            format!("{} Wrong password", icon::DELETE),
                                            std::time::Instant::now(),
                                        ));
                                    }
                                    app.password_input.clear();
                                }
                            }
                        }
                        // Remove encryption
                        if ui.add(theme::subtle_button("Remove Encryption")).clicked() {
                            if !app.password_input.is_empty() {
                                let key = crate::storage::derive_key_from_password(&app.password_input);
                                if let Ok(mut db) = app.db.lock() {
                                    // Temporarily set session key so decrypt_private_keys can read raw keys
                                    db.set_session_key(None);
                                    match db.decrypt_private_keys(&key) {
                                        Ok(()) => {
                                            let _ = db.set_setting("keys_encrypted", "0");
                                            db.set_session_key(None);
                                            app.keys_encrypted = false;
                                            app.session_key = None;
                                            app.notifications.push((
                                                format!("{} Encryption removed", icon::CHECK),
                                                std::time::Instant::now(),
                                            ));
                                        }
                                        Err(e) => {
                                            app.notifications.push((
                                                format!("{} Wrong password: {e}", icon::DELETE),
                                                std::time::Instant::now(),
                                            ));
                                        }
                                    }
                                }
                                app.password_input.clear();
                                app.refresh_data();
                            }
                        }
                    });
                } else {
                    ui.label(
                        RichText::new("Private keys are NOT encrypted")
                            .color(theme::WARNING)
                            .size(13.0),
                    );
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("New password:").color(theme::TEXT_DIM).size(13.0));
                        ui.add(egui::TextEdit::singleline(&mut app.password_input)
                            .password(true)
                            .hint_text("Enter password")
                            .desired_width(200.0));
                    });
                    if ui.add(theme::accent_button("Encrypt Keys")).clicked() {
                        if !app.password_input.is_empty() {
                            let key = crate::storage::derive_key_from_password(&app.password_input);
                            if let Ok(mut db) = app.db.lock() {
                                match db.encrypt_private_keys(&key) {
                                    Ok(()) => {
                                        app.keys_encrypted = true;
                                        app.session_key = Some(key);
                                        db.set_session_key(Some(key));
                                        app.notifications.push((
                                            format!("{} Keys encrypted", icon::CHECK),
                                            std::time::Instant::now(),
                                        ));
                                    }
                                    Err(e) => {
                                        app.notifications.push((
                                            format!("{} Error: {e}", icon::DELETE),
                                            std::time::Instant::now(),
                                        ));
                                    }
                                }
                            }
                            app.password_input.clear();
                        }
                    }
                }
            });

            // About
            settings_section(ui, &theme::icon_text(icon::KEY, "About"), |ui| {
                ui.label(
                    RichText::new("Bitmessage-RS")
                        .size(14.0)
                        .strong()
                        .color(theme::ACCENT),
                );
                ui.label(
                    RichText::new("Version 0.5.0")
                        .color(theme::TEXT_SECONDARY)
                        .size(12.0),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "A decentralized, encrypted messaging client.\n\
                         Compatible with the Bitmessage protocol v3.",
                    )
                    .color(theme::TEXT_DIM)
                    .size(12.0),
                );
                ui.add_space(4.0);
                ui.label(
                    RichText::new("Built with Rust + egui")
                        .color(theme::TEXT_DIM)
                        .size(11.0),
                );
            });
        });
}

pub fn render_network_status(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    // Header
    theme::header_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::NETWORK).size(18.0).color(theme::ACCENT));
            ui.label(RichText::new("Network Status").size(18.0).strong());
            ui.add_space(16.0);
            let color = if app.peer_count > 0 {
                theme::SUCCESS
            } else {
                theme::ERROR
            };
            ui.label(RichText::new(icon::DOT).color(color));
            ui.label(
                RichText::new(if app.peer_count > 0 {
                    "Connected"
                } else {
                    "Disconnected"
                })
                .color(color)
                .size(13.0),
            );
        });
    });

    egui::ScrollArea::vertical()
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.add_space(16.0);

            // Tor status
            settings_section(ui, &theme::icon_text(icon::LOCK, "Tor Network"), |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Status:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    let (color, text) = if app.tor_connected {
                        (theme::SUCCESS, "Connected")
                    } else {
                        (theme::ERROR, "Disconnected")
                    };
                    ui.label(RichText::new(icon::DOT).color(color).size(13.0));
                    ui.label(
                        RichText::new(text)
                            .color(color)
                            .size(13.0)
                            .strong(),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Bootstrap:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(
                        RichText::new(format!("{}%", app.tor_bootstrap_pct))
                            .size(13.0),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Info:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(
                        RichText::new(&app.tor_status_message)
                            .color(theme::TEXT_SECONDARY)
                            .size(13.0),
                    );
                });

                ui.add_space(4.0);
                ui.label(
                    RichText::new("All connections are routed through the Tor network")
                        .color(theme::TEXT_DIM)
                        .size(11.0),
                );
            });

            // Connection stats
            settings_section(ui, &theme::icon_text(icon::NETWORK, "Connections"), |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Active peers:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(
                        RichText::new(app.peer_count.to_string())
                            .size(13.0)
                            .strong(),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Status:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(
                        RichText::new(&app.status_message)
                            .color(theme::TEXT_SECONDARY)
                            .size(13.0),
                    );
                });
            });

            // Network statistics
            settings_section(ui, &theme::icon_text(icon::STAR, "Traffic"), |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Objects received:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(RichText::new(app.objects_received.to_string()).size(13.0));
                });
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Objects processed:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(RichText::new(app.objects_processed.to_string()).size(13.0));
                });
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Bytes sent:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(RichText::new(format_bytes(app.bytes_sent)).size(13.0));
                });
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Bytes received:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(RichText::new(format_bytes(app.bytes_received)).size(13.0));
                });
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Inventory objects:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(RichText::new(app.inventory_count.to_string()).size(13.0));
                });
            });

            // Data stats
            settings_section(ui, &theme::icon_text(icon::IDENTITY, "Data"), |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Identities:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(
                        RichText::new(app.identities.len().to_string()).size(13.0),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Contacts:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(
                        RichText::new(app.contacts.len().to_string()).size(13.0),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Inbox messages:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(
                        RichText::new(app.inbox.len().to_string()).size(13.0),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Sent messages:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(
                        RichText::new(app.sent.len().to_string()).size(13.0),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Channels:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(
                        RichText::new(app.channels.len().to_string()).size(13.0),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Subscriptions:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(
                        RichText::new(app.subscriptions.len().to_string()).size(13.0),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Blacklist entries:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(
                        RichText::new(app.blacklist.len().to_string()).size(13.0),
                    );
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Trash messages:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(
                        RichText::new(app.trash.len().to_string()).size(13.0),
                    );
                    if !app.trash.is_empty() {
                        if ui.add(theme::subtle_button(&theme::icon_text(icon::DELETE, "Empty Trash"))).clicked() {
                            if let Ok(db) = app.db.lock() {
                                let _ = db.empty_trash();
                            }
                            app.refresh_data();
                        }
                    }
                });
            });

            // Bootstrap nodes
            settings_section(ui, &theme::icon_text(icon::DOT, "Bootstrap Nodes"), |ui| {
                for &(host, port) in crate::network::BOOTSTRAP_NODES {
                    ui.label(
                        RichText::new(format!("{host}:{port}"))
                            .color(theme::TEXT_SECONDARY)
                            .size(12.0),
                    );
                }
                ui.add_space(4.0);
                ui.label(
                    RichText::new("DNS Seeds:")
                        .color(theme::TEXT_DIM)
                        .size(11.0),
                );
                for &seed in crate::network::DNS_SEEDS {
                    ui.label(
                        RichText::new(seed)
                            .color(theme::TEXT_SECONDARY)
                            .size(12.0),
                    );
                }
            });
        });
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn settings_section(ui: &mut egui::Ui, title: &str, content: impl FnOnce(&mut egui::Ui)) {
    egui::Frame {
        fill: theme::BG_PANEL,
        inner_margin: egui::Margin::symmetric(20.0, 16.0),
        rounding: egui::Rounding::same(8.0),
        outer_margin: egui::Margin::symmetric(16.0, 4.0),
        stroke: egui::Stroke::new(0.5, theme::BORDER),
        ..Default::default()
    }
    .show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(
            RichText::new(title)
                .size(13.0)
                .strong()
                .color(theme::TEXT_PRIMARY),
        );
        ui.add_space(8.0);
        content(ui);
    });
}
