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
                    ui.label(RichText::new("8").size(13.0));
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
                    ui.label(RichText::new("1000").size(13.0));
                });

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Default extra bytes:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(RichText::new("1000").size(13.0));
                });
            });

            // Message settings
            settings_section(ui, &theme::icon_text(icon::INBOX, "Messages"), |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Default TTL:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.label(RichText::new("4 days").size(13.0));
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
