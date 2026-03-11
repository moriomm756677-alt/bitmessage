use eframe::egui::{self, RichText};
use super::app::BitmessageApp;
use super::theme;
use super::theme::icon;

pub fn render_blacklist(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    // Header
    theme::header_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::LOCK).size(18.0).color(theme::ACCENT));
            ui.label(RichText::new("Blacklist").size(18.0).strong());
            ui.add_space(16.0);
            ui.label(
                RichText::new(format!("{} entries", app.blacklist.len()))
                    .color(theme::TEXT_DIM)
                    .size(12.0),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(theme::accent_button(&theme::icon_text(icon::ADD, "Add to Blacklist")))
                    .clicked()
                {
                    app.show_add_blacklist = true;
                    app.new_blacklist_label.clear();
                    app.new_blacklist_address.clear();
                }
            });
        });
    });

    // Add blacklist dialog
    if app.show_add_blacklist {
        render_add_blacklist_dialog(app, ui);
    }

    if app.blacklist.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.label(
                RichText::new("No blacklisted addresses")
                    .color(theme::TEXT_DIM)
                    .size(16.0),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new("Messages from blacklisted addresses will be ignored")
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
            let entries = app.blacklist.clone();
            for entry in &entries {
                let entry_id = entry.id;
                let enabled = entry.enabled;

                theme::card_frame().show(ui, |ui| {
                    ui.set_width(ui.available_width() - 32.0);
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&entry.label).strong().size(14.0));
                                if !enabled {
                                    ui.label(
                                        RichText::new("(disabled)")
                                            .color(theme::TEXT_DIM)
                                            .size(11.0),
                                    );
                                }
                            });
                            ui.label(
                                RichText::new(&entry.address)
                                    .color(theme::ERROR)
                                    .size(11.0),
                            );
                        });
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if ui
                                    .add(theme::subtle_button(&theme::icon_text(icon::DELETE, "Remove")))
                                    .clicked()
                                {
                                    if let Ok(db) = app.db.lock() {
                                        let _ = db.delete_blacklist(entry_id);
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
                                        let _ = db.toggle_blacklist(entry_id, !enabled);
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

fn render_add_blacklist_dialog(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    egui::Frame {
        fill: theme::BG_PANEL,
        inner_margin: egui::Margin::symmetric(20.0, 16.0),
        rounding: egui::Rounding::same(10.0),
        outer_margin: egui::Margin::symmetric(16.0, 8.0),
        stroke: egui::Stroke::new(1.0, theme::ACCENT_MUTED),
        ..Default::default()
    }
    .show(ui, |ui| {
        ui.label(
            RichText::new(theme::icon_text(icon::LOCK, "Add to Blacklist"))
                .size(14.0)
                .strong(),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new("Messages from this address will be silently ignored.")
                .color(theme::TEXT_DIM)
                .size(11.0),
        );
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label(RichText::new("Label:").color(theme::TEXT_DIM).size(13.0));
            ui.add_space(8.0);
            ui.add(
                egui::TextEdit::singleline(&mut app.new_blacklist_label)
                    .hint_text("Spammer")
                    .desired_width(250.0),
            );
        });

        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.label(RichText::new("Address:").color(theme::TEXT_DIM).size(13.0));
            ui.add(
                egui::TextEdit::singleline(&mut app.new_blacklist_address)
                    .hint_text("BM-...")
                    .desired_width(250.0),
            );
        });

        ui.add_space(8.0);

        ui.horizontal(|ui| {
            let can_add = !app.new_blacklist_label.is_empty()
                && !app.new_blacklist_address.is_empty();
            ui.add_enabled_ui(can_add, |ui| {
                if ui
                    .add(theme::accent_button(&theme::icon_text(icon::CHECK, "Add")))
                    .clicked()
                {
                    if let Ok(db) = app.db.lock() {
                        let _ = db.insert_blacklist(
                            &app.new_blacklist_label,
                            &app.new_blacklist_address,
                        );
                    }
                    app.refresh_data();
                    app.show_add_blacklist = false;
                }
            });
            if ui.add(theme::subtle_button("Cancel")).clicked() {
                app.show_add_blacklist = false;
            }
        });
    });
}
