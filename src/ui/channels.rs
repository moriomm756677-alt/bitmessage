use eframe::egui::{self, RichText};
use super::app::BitmessageApp;
use super::theme;
use super::theme::icon;
use crate::crypto::address::BitmessageAddress;

pub fn render_channels(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    // Header
    theme::header_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::CHANNELS).size(18.0).color(theme::ACCENT));
            ui.label(RichText::new("Channels").size(18.0).strong());
            ui.add_space(16.0);
            ui.label(
                RichText::new(format!("{} channels", app.channels.len()))
                    .color(theme::TEXT_DIM)
                    .size(12.0),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(theme::accent_button(&theme::icon_text(icon::ADD, "Join Channel"))).clicked() {
                    app.show_join_channel = true;
                    app.new_channel_passphrase.clear();
                }
            });
        });
    });

    // Join channel dialog
    if app.show_join_channel {
        render_join_channel_dialog(app, ui);
    }

    // Channel list
    if app.channels.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.label(
                RichText::new("No channels")
                    .color(theme::TEXT_DIM)
                    .size(16.0),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new("Join a channel with a passphrase to participate in group discussions")
                    .color(theme::TEXT_DIM)
                    .size(12.0),
            );
        });
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.add_space(8.0);
            let channels = app.channels.clone();
            for channel in &channels {
                render_channel_card(app, ui, channel);
            }
        });
}

fn render_channel_card(
    app: &mut BitmessageApp,
    ui: &mut egui::Ui,
    channel: &crate::storage::StoredChannel,
) {
    let channel_id = channel.id;

    theme::card_frame().show(ui, |ui| {
        ui.set_width(ui.available_width() - 32.0);
        ui.horizontal(|ui| {
            // Channel icon
            let (rect, _) = ui.allocate_exact_size(egui::vec2(40.0, 40.0), egui::Sense::hover());
            ui.painter()
                .rect_filled(rect, egui::Rounding::same(8.0), theme::ACCENT_MUTED);
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                "#",
                egui::FontId::proportional(18.0),
                egui::Color32::WHITE,
            );

            ui.add_space(8.0);

            ui.vertical(|ui| {
                ui.label(
                    RichText::new(format!("[chan] {}", channel.label))
                        .strong()
                        .size(14.0),
                );
                ui.label(
                    RichText::new(&channel.address)
                        .color(theme::ACCENT)
                        .size(11.0),
                );
                let status = if channel.enabled { "Active" } else { "Disabled" };
                let color = if channel.enabled {
                    theme::SUCCESS
                } else {
                    theme::TEXT_DIM
                };
                ui.label(RichText::new(status).color(color).size(10.0));
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(theme::subtle_button(&theme::icon_text(icon::DELETE, "Leave"))).clicked() {
                    if let Ok(db) = app.db.lock() {
                        let _ = db.delete_channel(channel_id);
                    }
                    app.refresh_data();
                }
                if ui.add(theme::subtle_button(&theme::icon_text(icon::SEND, "Send"))).clicked() {
                    app.compose.to = channel.address.clone();
                    app.compose.is_broadcast = false;
                    app.current_view = super::app::View::Compose;
                }
            });
        });
    });

    ui.add_space(2.0);
}

fn render_join_channel_dialog(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    egui::Frame {
        fill: theme::BG_PANEL,
        inner_margin: egui::Margin::symmetric(20.0, 16.0),
        rounding: egui::Rounding::same(10.0),
        outer_margin: egui::Margin::symmetric(16.0, 8.0),
        stroke: egui::Stroke::new(1.0, theme::ACCENT_MUTED),
        ..Default::default()
    }
    .show(ui, |ui| {
        ui.label(RichText::new(theme::icon_text(icon::CHANNELS, "Join / Create Channel")).size(14.0).strong());
        ui.add_space(4.0);
        ui.label(
            RichText::new("Enter a passphrase. Anyone with the same passphrase can join this channel.")
                .color(theme::TEXT_DIM)
                .size(11.0),
        );
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Passphrase:")
                    .color(theme::TEXT_DIM)
                    .size(13.0),
            );
            ui.add(
                egui::TextEdit::singleline(&mut app.new_channel_passphrase)
                    .hint_text("Channel passphrase")
                    .desired_width(300.0),
            );
        });

        ui.add_space(8.0);

        ui.horizontal(|ui| {
            let can_join = !app.new_channel_passphrase.is_empty();
            ui.add_enabled_ui(can_join, |ui| {
                if ui.add(theme::accent_button(&theme::icon_text(icon::CHECK, "Join"))).clicked() {
                    match BitmessageAddress::from_passphrase(&app.new_channel_passphrase) {
                        Ok((addr, _keypair)) => {
                            if let Ok(db) = app.db.lock() {
                                let _ = db.insert_channel(
                                    &app.new_channel_passphrase,
                                    &addr.encoded,
                                    &app.new_channel_passphrase,
                                );
                            }
                            app.refresh_data();
                            app.show_join_channel = false;
                        }
                        Err(e) => {
                            app.notifications.push((
                                format!("Channel error: {e}"),
                                std::time::Instant::now(),
                            ));
                        }
                    }
                }
            });
            if ui.add(theme::subtle_button("Cancel")).clicked() {
                app.show_join_channel = false;
            }
        });
    });
}

// --- Subscriptions ---

pub fn render_subscriptions(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    // Header
    theme::header_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::SUBS).size(18.0).color(theme::ACCENT));
            ui.label(RichText::new("Subscriptions").size(18.0).strong());
            ui.add_space(16.0);
            ui.label(
                RichText::new(format!("{} subscriptions", app.subscriptions.len()))
                    .color(theme::TEXT_DIM)
                    .size(12.0),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(theme::accent_button(&theme::icon_text(icon::ADD, "Subscribe"))).clicked() {
                    app.show_add_subscription = true;
                    app.new_sub_label.clear();
                    app.new_sub_address.clear();
                }
            });
        });
    });

    // Add subscription dialog
    if app.show_add_subscription {
        render_add_subscription_dialog(app, ui);
    }

    if app.subscriptions.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.label(
                RichText::new("No subscriptions")
                    .color(theme::TEXT_DIM)
                    .size(16.0),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new("Subscribe to addresses to receive their broadcast messages")
                    .color(theme::TEXT_DIM)
                    .size(12.0),
            );
        });
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.add_space(8.0);
            let subs = app.subscriptions.clone();
            for sub in &subs {
                let sub_id = sub.id;
                theme::card_frame().show(ui, |ui| {
                    ui.set_width(ui.available_width() - 32.0);
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&sub.label).strong().size(14.0));
                            ui.label(
                                RichText::new(&sub.address)
                                    .color(theme::ACCENT)
                                    .size(11.0),
                            );
                        });
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if ui.add(theme::subtle_button(&theme::icon_text(icon::DELETE, "Unsubscribe"))).clicked() {
                                    if let Ok(db) = app.db.lock() {
                                        let _ = db.delete_subscription(sub_id);
                                    }
                                    app.refresh_data();
                                }
                            },
                        );
                    });
                });
                ui.add_space(2.0);
            }
        });
}

fn render_add_subscription_dialog(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    egui::Frame {
        fill: theme::BG_PANEL,
        inner_margin: egui::Margin::symmetric(20.0, 16.0),
        rounding: egui::Rounding::same(10.0),
        outer_margin: egui::Margin::symmetric(16.0, 8.0),
        stroke: egui::Stroke::new(1.0, theme::ACCENT_MUTED),
        ..Default::default()
    }
    .show(ui, |ui| {
        ui.label(RichText::new(theme::icon_text(icon::SUBS, "Add Subscription")).size(14.0).strong());
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label(RichText::new("Label:").color(theme::TEXT_DIM));
            ui.add(
                egui::TextEdit::singleline(&mut app.new_sub_label)
                    .hint_text("Subscription label")
                    .desired_width(250.0),
            );
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Address:").color(theme::TEXT_DIM));
            ui.add(
                egui::TextEdit::singleline(&mut app.new_sub_address)
                    .hint_text("BM-...")
                    .desired_width(250.0),
            );
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let can_add = !app.new_sub_label.is_empty() && !app.new_sub_address.is_empty();
            ui.add_enabled_ui(can_add, |ui| {
                if ui.add(theme::accent_button(&theme::icon_text(icon::CHECK, "Subscribe"))).clicked() {
                    if let Ok(db) = app.db.lock() {
                        let _ = db.insert_subscription(&app.new_sub_label, &app.new_sub_address);
                    }
                    app.refresh_data();
                    app.show_add_subscription = false;
                }
            });
            if ui.add(theme::subtle_button("Cancel")).clicked() {
                app.show_add_subscription = false;
            }
        });
    });
}
