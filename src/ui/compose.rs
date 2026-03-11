use eframe::egui::{self, RichText};
use super::app::{BitmessageApp, View};
use super::bbcode;
use super::theme;
use super::theme::icon;
use crate::network::NetworkCommand;

pub fn render_compose(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    // Header
    theme::header_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(icon::COMPOSE).size(18.0).color(theme::ACCENT));
            ui.label(RichText::new("Compose").size(18.0).strong());
            ui.add_space(16.0);

            // Broadcast toggle
            ui.checkbox(&mut app.compose.is_broadcast, "Broadcast");
        });
    });

    egui::ScrollArea::vertical()
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.add_space(16.0);

            egui::Frame {
                fill: theme::BG_PANEL,
                inner_margin: egui::Margin::symmetric(24.0, 20.0),
                rounding: egui::Rounding::same(8.0),
                outer_margin: egui::Margin::symmetric(16.0, 0.0),
                stroke: egui::Stroke::new(0.5, theme::BORDER),
                ..Default::default()
            }
            .show(ui, |ui| {
                let width = ui.available_width();

                // From address
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("From:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.add_space(8.0);
                    if app.identities.is_empty() {
                        ui.label(
                            RichText::new("No identities - create one first")
                                .color(theme::ERROR)
                                .size(13.0),
                        );
                    } else {
                        let selected = app.compose.from_idx.min(app.identities.len() - 1);
                        let current = &app.identities[selected];
                        egui::ComboBox::from_id_salt("from_address")
                            .selected_text(format!("{} ({})", current.label, shorten(&current.address)))
                            .width(width - 80.0)
                            .show_ui(ui, |ui| {
                                for (i, identity) in app.identities.iter().enumerate() {
                                    let text = format!(
                                        "{} ({})",
                                        identity.label,
                                        shorten(&identity.address)
                                    );
                                    ui.selectable_value(
                                        &mut app.compose.from_idx,
                                        i,
                                        text,
                                    );
                                }
                            });
                    }
                });

                ui.add_space(8.0);

                // To address (not for broadcasts)
                if !app.compose.is_broadcast {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("To:")
                                .color(theme::TEXT_DIM)
                                .size(13.0),
                        );
                        ui.add_space(20.0);
                        ui.add(
                            egui::TextEdit::singleline(&mut app.compose.to)
                                .hint_text("BM-...")
                                .desired_width(width - 80.0),
                        );
                    });

                    // Address validation
                    if !app.compose.to.is_empty() && !app.compose.is_broadcast {
                        let valid = app.compose.to.starts_with("BM-")
                            && crate::crypto::address::BitmessageAddress::decode(&app.compose.to).is_ok();
                        if !valid {
                            ui.label(
                                RichText::new("Invalid Bitmessage address")
                                    .color(theme::ERROR)
                                    .size(11.0),
                            );
                        }
                    }

                    // Quick contact picker
                    if !app.contacts.is_empty() && app.compose.to.is_empty() {
                        ui.add_space(4.0);
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new("Quick pick:")
                                    .color(theme::TEXT_DIM)
                                    .size(11.0),
                            );
                            for contact in &app.contacts {
                                if ui
                                    .add(theme::subtle_button(&contact.label))
                                    .clicked()
                                {
                                    app.compose.to = contact.address.clone();
                                }
                            }
                        });
                    }

                    ui.add_space(8.0);
                }

                // Subject
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Subject:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut app.compose.subject)
                            .hint_text("Subject")
                            .desired_width(width - 80.0),
                    );
                });

                ui.add_space(12.0);

                // Body — mode toggle + toolbar/editor
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Message:")
                            .color(theme::TEXT_DIM)
                            .size(13.0),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        mode_toggle(ui, &mut app.compose.visual_mode);
                    });
                });
                ui.add_space(4.0);

                if app.compose.visual_mode {
                    // ── Visual mode: rendered BBCode ──
                    egui::Frame {
                        fill: theme::BG_DARKEST,
                        inner_margin: egui::Margin::symmetric(16.0, 12.0),
                        rounding: egui::Rounding::same(6.0),
                        stroke: egui::Stroke::new(0.5, theme::BORDER),
                        ..Default::default()
                    }
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.set_min_height(200.0);
                        if app.compose.body.is_empty() {
                            ui.label(
                                RichText::new("Write your message...")
                                    .color(theme::TEXT_DIM)
                                    .size(13.0)
                                    .italics(),
                            );
                        } else {
                            bbcode::render_bbcode(ui, &app.compose.body);
                        }
                    });
                } else {
                    // ── Edit mode: toolbar + source editor ──
                    bbcode::bbcode_toolbar(ui, &mut app.compose.body, &mut app.compose.body_cursor);
                    ui.add_space(4.0);

                    let output = egui::TextEdit::multiline(&mut app.compose.body)
                        .hint_text("Write your message...")
                        .desired_rows(12)
                        .desired_width(width)
                        .show(ui);

                    // Track cursor for toolbar tag insertion
                    if let Some(cursor_range) = output.cursor_range {
                        let start = cursor_range.primary.ccursor.index
                            .min(cursor_range.secondary.ccursor.index);
                        let end = cursor_range.primary.ccursor.index
                            .max(cursor_range.secondary.ccursor.index);
                        app.compose.body_cursor = Some((start, end));
                    }
                }

                ui.add_space(12.0);

                // Attachment section
                if !app.compose.is_broadcast {
                    ui.horizontal(|ui| {
                        if ui.add(theme::subtle_button(
                            &theme::icon_text(icon::ATTACH, "Attach File")
                        )).clicked() {
                            if let Some(path) = rfd::FileDialog::new().pick_file() {
                                if let Ok(data) = std::fs::read(&path) {
                                    let filename = path.file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_else(|| "file".into());
                                    let mime_type = mime_from_ext(&filename);
                                    let size = data.len();
                                    if size > 10 * 1024 * 1024 {
                                        // 10 MB limit
                                        app.notifications.push((
                                            format!("{} File too large (max 10 MB)", icon::DELETE),
                                            std::time::Instant::now(),
                                        ));
                                    } else {
                                        app.compose.attached_file = Some(super::app::AttachedFile {
                                            filename,
                                            mime_type,
                                            data,
                                        });
                                    }
                                }
                            }
                        }

                        // Show attached file info
                        if let Some(ref file) = app.compose.attached_file {
                            ui.add_space(8.0);
                            ui.label(
                                RichText::new(format!(
                                    "{} {} ({})",
                                    icon::FILE, file.filename, format_file_size(file.data.len() as u64)
                                ))
                                .color(theme::ACCENT)
                                .size(12.0),
                            );
                            if ui.add(theme::subtle_button(&icon::DELETE.to_string())).clicked() {
                                app.compose.attached_file = None;
                            }
                        }
                    });
                }

                ui.add_space(8.0);

                // Send button
                ui.horizontal(|ui| {
                    let to_valid = app.compose.is_broadcast
                        || (app.compose.to.starts_with("BM-")
                            && crate::crypto::address::BitmessageAddress::decode(&app.compose.to).is_ok());
                    let can_send = !app.identities.is_empty()
                        && (app.compose.is_broadcast || !app.compose.to.is_empty())
                        && to_valid
                        && (!app.compose.body.is_empty() || app.compose.attached_file.is_some());

                    ui.add_enabled_ui(can_send, |ui| {
                        let label = if app.compose.is_broadcast {
                            theme::icon_text(icon::SEND, "Send Broadcast")
                        } else {
                            theme::icon_text(icon::SEND, "Send Message")
                        };
                        if ui
                            .add(theme::accent_button(&label).min_size(egui::vec2(140.0, 36.0)))
                            .clicked()
                        {
                            send_message(app);
                        }
                    });

                    ui.add_space(8.0);
                    if ui.add(theme::subtle_button(&theme::icon_text(icon::DELETE, "Discard"))).clicked() {
                        app.compose = super::app::ComposeState::default();
                        app.current_view = View::Inbox;
                    }

                    if !can_send && !app.identities.is_empty() {
                        ui.label(
                            RichText::new("Fill in all required fields")
                                .color(theme::TEXT_DIM)
                                .size(11.0),
                        );
                    }
                });
            });
        });
}

fn send_message(app: &mut BitmessageApp) {
    let from_idx = app.compose.from_idx.min(app.identities.len().saturating_sub(1));
    let from_address = if let Some(id) = app.identities.get(from_idx) {
        id.address.clone()
    } else {
        return;
    };

    // Generate msgid and store in DB first
    let msgid = hex::encode(rand::random::<[u8; 16]>());
    if let Ok(db) = app.db.lock() {
        let to = if app.compose.is_broadcast {
            "[Broadcast]"
        } else {
            &app.compose.to
        };
        let status = if app.compose.is_broadcast {
            "broadcastqueued"
        } else {
            "msgqueued"
        };
        let _ = db.insert_message(
            &msgid,
            &from_address,
            to,
            &app.compose.subject,
            &app.compose.body,
            2,
            status,
            "sent",
        );
    }

    // Send command with msgid so network layer can update status
    let cmd = if app.compose.is_broadcast {
        NetworkCommand::SendBroadcast {
            msgid,
            from_address: from_address.clone(),
            subject: app.compose.subject.clone(),
            body: app.compose.body.clone(),
        }
    } else {
        NetworkCommand::SendMessage {
            msgid,
            from_address: from_address.clone(),
            to_address: app.compose.to.clone(),
            subject: app.compose.subject.clone(),
            body: app.compose.body.clone(),
            attachment: app.compose.attached_file.take().map(|f| {
                crate::network::AttachmentData {
                    filename: f.filename,
                    mime_type: f.mime_type,
                    data: f.data,
                }
            }),
        }
    };

    let _ = app.cmd_tx.send(cmd);

    app.compose = super::app::ComposeState::default();
    app.refresh_data();
    app.current_view = View::Sent;
}

fn format_file_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn mime_from_ext(filename: &str) -> String {
    let ext = filename.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "txt" => "text/plain",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "zip" => "application/zip",
        "tar" => "application/x-tar",
        "gz" => "application/gzip",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "doc" | "docx" => "application/msword",
        _ => "application/octet-stream",
    }.to_string()
}

fn shorten(addr: &str) -> String {
    if addr.len() > 20 {
        format!("{}...{}", &addr[..12], &addr[addr.len() - 6..])
    } else {
        addr.to_string()
    }
}

/// Pill-shaped segmented toggle: [Edit | Visual]
fn mode_toggle(ui: &mut egui::Ui, visual_mode: &mut bool) {
    let total_w = 120.0_f32;
    let h = 22.0_f32;
    let half = total_w / 2.0;
    let rounding = h / 2.0;

    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(total_w, h),
        egui::Sense::click(),
    );

    if response.clicked() {
        // Determine which half was clicked
        if let Some(pos) = response.interact_pointer_pos() {
            *visual_mode = pos.x > rect.center().x;
        }
    }

    let painter = ui.painter();

    // Outer pill background
    painter.rect_filled(rect, rounding, theme::BG_DARKEST);
    painter.rect_stroke(rect, rounding, egui::Stroke::new(0.5, theme::BORDER_LIGHT));

    // Active segment highlight
    let active_rect = if *visual_mode {
        egui::Rect::from_min_size(
            egui::pos2(rect.min.x + half, rect.min.y),
            egui::vec2(half, h),
        )
    } else {
        egui::Rect::from_min_size(rect.min, egui::vec2(half, h))
    };
    painter.rect_filled(
        active_rect.shrink(1.5),
        rounding - 1.0,
        theme::ACCENT_DIM,
    );

    // Labels
    let edit_center = egui::pos2(rect.min.x + half * 0.5, rect.center().y);
    let visual_center = egui::pos2(rect.min.x + half * 1.5, rect.center().y);

    let edit_color = if *visual_mode { theme::TEXT_DIM } else { theme::TEXT_PRIMARY };
    let visual_color = if *visual_mode { theme::TEXT_PRIMARY } else { theme::TEXT_DIM };

    painter.text(
        edit_center,
        egui::Align2::CENTER_CENTER,
        format!("{} Edit", icon::COMPOSE),
        egui::FontId::proportional(11.0),
        edit_color,
    );
    painter.text(
        visual_center,
        egui::Align2::CENTER_CENTER,
        format!("{} Visual", icon::SEARCH),
        egui::FontId::proportional(11.0),
        visual_color,
    );

    // Thin divider line in the middle
    let mid_x = rect.min.x + half;
    painter.line_segment(
        [egui::pos2(mid_x, rect.min.y + 5.0), egui::pos2(mid_x, rect.max.y - 5.0)],
        egui::Stroke::new(0.5, theme::BORDER_LIGHT),
    );
}
