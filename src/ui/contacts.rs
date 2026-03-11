use eframe::egui::{self, RichText};
use super::app::BitmessageApp;
use super::theme;
use super::theme::icon;

pub fn render_contacts(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    // Header
    theme::header_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::CONTACTS).size(18.0).color(theme::ACCENT));
            ui.label(RichText::new("Contacts").size(18.0).strong());
            ui.add_space(16.0);
            ui.label(
                RichText::new(format!("{} contacts", app.contacts.len()))
                    .color(theme::TEXT_DIM)
                    .size(12.0),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(theme::accent_button(&theme::icon_text(icon::ADD, "Add Contact"))).clicked() {
                    app.show_add_contact = true;
                    app.new_contact_label.clear();
                    app.new_contact_address.clear();
                }
            });
        });
    });

    // Add contact dialog
    if app.show_add_contact {
        render_add_contact_dialog(app, ui);
    }

    // Contact list
    if app.contacts.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.label(
                RichText::new("No contacts yet")
                    .color(theme::TEXT_DIM)
                    .size(16.0),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new("Add contacts to easily send them messages")
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
            let contacts = app.contacts.clone();
            for contact in &contacts {
                render_contact_card(app, ui, contact);
            }
        });
}

fn render_contact_card(
    app: &mut BitmessageApp,
    ui: &mut egui::Ui,
    contact: &crate::storage::StoredContact,
) {
    let contact_id = contact.id;

    egui::Frame {
        fill: theme::BG_SURFACE,
        inner_margin: egui::Margin::symmetric(16.0, 12.0),
        rounding: egui::Rounding::same(8.0),
        outer_margin: egui::Margin::symmetric(16.0, 3.0),
        stroke: egui::Stroke::new(0.5, theme::BORDER),
        ..Default::default()
    }
    .show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal(|ui| {
            // Avatar circle
            let (rect, _) = ui.allocate_exact_size(egui::vec2(40.0, 40.0), egui::Sense::hover());
            let initial = contact
                .label
                .chars()
                .next()
                .unwrap_or('?')
                .to_uppercase()
                .next()
                .unwrap_or('?');
            let color = name_color(&contact.label);
            ui.painter()
                .rect_filled(rect, egui::Rounding::same(20.0), color);
            ui.painter().text(
                rect.center(),
                egui::Align2::CENTER_CENTER,
                initial,
                egui::FontId::proportional(16.0),
                egui::Color32::WHITE,
            );

            ui.add_space(8.0);

            ui.vertical(|ui| {
                ui.label(RichText::new(&contact.label).strong().size(14.0));
                ui.label(
                    RichText::new(&contact.address)
                        .color(theme::ACCENT)
                        .size(11.0),
                );
                if contact.pub_signing_key.is_some() {
                    ui.label(
                        RichText::new(format!("{} Public key available", icon::CHECK))
                            .color(theme::SUCCESS)
                            .size(10.0),
                    );
                }
            });

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(theme::subtle_button(&theme::icon_text(icon::DELETE, "Delete"))).clicked() {
                    if let Ok(db) = app.db.lock() {
                        let _ = db.delete_contact(contact_id);
                    }
                    app.refresh_data();
                }
                if ui.add(theme::subtle_button(&theme::icon_text(icon::COMPOSE, "Message"))).clicked() {
                    app.compose.to = contact.address.clone();
                    app.compose.is_broadcast = false;
                    app.current_view = super::app::View::Compose;
                }
            });
        });
    });
}

fn render_add_contact_dialog(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    egui::Frame {
        fill: theme::BG_PANEL,
        inner_margin: egui::Margin::symmetric(20.0, 16.0),
        rounding: egui::Rounding::same(10.0),
        outer_margin: egui::Margin::symmetric(16.0, 8.0),
        stroke: egui::Stroke::new(1.0, theme::ACCENT_MUTED),
        ..Default::default()
    }
    .show(ui, |ui| {
        ui.label(RichText::new(theme::icon_text(icon::ADD, "Add Contact")).size(14.0).strong());
        ui.add_space(8.0);

        ui.horizontal(|ui| {
            ui.label(RichText::new("Name:").color(theme::TEXT_DIM).size(13.0));
            ui.add_space(8.0);
            ui.add(
                egui::TextEdit::singleline(&mut app.new_contact_label)
                    .hint_text("Contact name")
                    .desired_width(250.0),
            );
        });

        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Address:")
                    .color(theme::TEXT_DIM)
                    .size(13.0),
            );
            ui.add(
                egui::TextEdit::singleline(&mut app.new_contact_address)
                    .hint_text("BM-...")
                    .desired_width(250.0),
            );
        });

        ui.add_space(8.0);

        ui.horizontal(|ui| {
            let can_add =
                !app.new_contact_label.is_empty() && !app.new_contact_address.is_empty();
            ui.add_enabled_ui(can_add, |ui| {
                if ui.add(theme::accent_button(&theme::icon_text(icon::CHECK, "Add"))).clicked() {
                    if let Ok(db) = app.db.lock() {
                        let _ = db.insert_contact(
                            &app.new_contact_label,
                            &app.new_contact_address,
                        );
                    }
                    app.refresh_data();
                    app.show_add_contact = false;
                }
            });
            if ui.add(theme::subtle_button("Cancel")).clicked() {
                app.show_add_contact = false;
            }
        });
    });
}

/// Generate a consistent color from a name
fn name_color(name: &str) -> egui::Color32 {
    let hash: u32 = name.bytes().fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));
    let hue = (hash % 360) as f32;
    egui::ecolor::Hsva::new(hue / 360.0, 0.5, 0.6, 1.0).into()
}
