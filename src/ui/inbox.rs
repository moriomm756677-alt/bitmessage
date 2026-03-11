use eframe::egui::{self, RichText, Color32};
use super::app::{BitmessageApp, View};
use super::bbcode;
use super::theme;
use super::theme::icon;

pub fn render_inbox(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    render_message_list(app, ui, "Inbox", "inbox");
}

pub fn render_sent(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    render_message_list(app, ui, "Sent", "sent");
}

pub fn render_trash(app: &mut BitmessageApp, ui: &mut egui::Ui) {
    render_message_list(app, ui, "Trash", "trash");
}

fn render_message_list(app: &mut BitmessageApp, ui: &mut egui::Ui, title: &str, folder: &str) {
    let messages: Vec<_> = match folder {
        "inbox" => app.inbox.clone(),
        "sent" => app.sent.clone(),
        "trash" => app.trash.clone(),
        _ => return,
    };

    let total_count = match folder {
        "inbox" => app.total_inbox,
        "sent" => app.total_sent,
        "trash" => app.total_trash,
        _ => 0,
    };

    let msg_count = messages.len();
    let sel_count = app.selected_messages.len();

    // Header
    let title_icon = match folder {
        "inbox" => icon::INBOX,
        "sent" => icon::SENT,
        "trash" => icon::TRASH,
        _ => icon::INBOX,
    };
    theme::header_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(title_icon).size(18.0).color(theme::ACCENT));
            ui.label(RichText::new(title).size(18.0).strong());
            ui.add_space(16.0);
            ui.label(
                RichText::new(format!("{msg_count} messages"))
                    .color(theme::TEXT_DIM)
                    .size(12.0),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut app.search_query)
                        .hint_text(format!("{} Search...", icon::SEARCH))
                        .desired_width(200.0),
                );
            });
        });
    });

    // Filter messages
    let query = app.search_query.to_lowercase();
    let filtered: Vec<_> = messages
        .iter()
        .filter(|m| {
            query.is_empty()
                || m.subject.to_lowercase().contains(&query)
                || m.from_address.to_lowercase().contains(&query)
                || m.body.to_lowercase().contains(&query)
        })
        .collect();

    // Batch action bar (shown when messages are selected)
    if sel_count > 0 {
        egui::Frame {
            fill: theme::BG_SURFACE,
            inner_margin: egui::Margin::symmetric(16.0, 8.0),
            stroke: egui::Stroke::new(0.5, theme::ACCENT_MUTED),
            ..Default::default()
        }
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{sel_count} selected"))
                        .color(theme::ACCENT)
                        .size(12.0)
                        .strong(),
                );
                ui.add_space(12.0);

                // Select all / Deselect all
                let all_ids: Vec<i64> = filtered.iter().map(|m| m.id).collect();
                let all_selected = !all_ids.is_empty()
                    && all_ids.iter().all(|id| app.selected_messages.contains(id));

                if all_selected {
                    if ui.add(theme::subtle_button("Deselect All")).clicked() {
                        app.selected_messages.clear();
                    }
                } else {
                    if ui.add(theme::subtle_button("Select All")).clicked() {
                        for id in &all_ids {
                            app.selected_messages.insert(*id);
                        }
                    }
                }

                ui.add_space(8.0);

                // Actions depending on folder
                if folder == "trash" {
                    // Restore
                    if ui.add(theme::subtle_button(
                        &theme::icon_text(icon::BACK, "Restore"),
                    )).clicked() {
                        let ids: Vec<i64> = app.selected_messages.iter().copied().collect();
                        if let Ok(db) = app.db.lock() {
                            for id in &ids {
                                let _ = db.untrash_message(*id);
                            }
                        }
                        app.selected_messages.clear();
                        app.refresh_data();
                    }
                    // Delete permanently
                    if ui.add(theme::subtle_button(
                        &theme::icon_text(icon::DELETE, "Delete"),
                    )).clicked() {
                        let ids: Vec<i64> = app.selected_messages.iter().copied().collect();
                        if let Ok(db) = app.db.lock() {
                            for id in &ids {
                                let _ = db.delete_message(*id);
                            }
                        }
                        app.selected_messages.clear();
                        app.refresh_data();
                    }
                } else {
                    // Mark as read (inbox only)
                    if folder == "inbox" {
                        if ui.add(theme::subtle_button(
                            &theme::icon_text(icon::CHECK, "Mark Read"),
                        )).clicked() {
                            let ids: Vec<i64> = app.selected_messages.iter().copied().collect();
                            if let Ok(db) = app.db.lock() {
                                for id in &ids {
                                    let _ = db.mark_message_read(*id);
                                }
                            }
                            app.selected_messages.clear();
                            app.refresh_data();
                        }
                    }

                    // Move to trash
                    if ui.add(theme::subtle_button(
                        &theme::icon_text(icon::TRASH, "Trash"),
                    )).clicked() {
                        let ids: Vec<i64> = app.selected_messages.iter().copied().collect();
                        if let Ok(db) = app.db.lock() {
                            for id in &ids {
                                let _ = db.trash_message(*id);
                            }
                        }
                        app.selected_messages.clear();
                        app.refresh_data();
                    }
                }
            });
        });
    }

    if filtered.is_empty() {
        ui.vertical_centered(|ui| {
            ui.add_space(80.0);
            ui.label(
                RichText::new("No messages")
                    .color(theme::TEXT_DIM)
                    .size(16.0),
            );
            if folder == "inbox" {
                ui.add_space(8.0);
                ui.label(
                    RichText::new("Messages you receive will appear here")
                        .color(theme::TEXT_DIM)
                        .size(12.0),
                );
            }
        });
        return;
    }

    egui::ScrollArea::vertical()
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.add_space(4.0);
            for msg in &filtered {
                let is_unread = !msg.read && folder == "inbox";
                render_message_row(app, ui, msg, is_unread, folder);
            }

            // Pagination controls
            if total_count > app.page_size {
                ui.add_space(8.0);
                egui::Frame {
                    fill: theme::BG_SURFACE,
                    inner_margin: egui::Margin::symmetric(16.0, 8.0),
                    ..Default::default()
                }
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let current_page = (app.page_offset / app.page_size) + 1;
                        let total_pages = (total_count + app.page_size - 1) / app.page_size;

                        ui.add_enabled_ui(app.page_offset > 0, |ui| {
                            if ui.add(theme::subtle_button(&theme::icon_text(icon::BACK, "Prev"))).clicked() {
                                app.page_offset = (app.page_offset - app.page_size).max(0);
                                app.refresh_data();
                            }
                        });

                        ui.label(
                            RichText::new(format!("Page {current_page} / {total_pages}"))
                                .color(theme::TEXT_SECONDARY)
                                .size(12.0),
                        );

                        ui.add_enabled_ui(app.page_offset + app.page_size < total_count, |ui| {
                            if ui.add(theme::subtle_button("Next")).clicked() {
                                app.page_offset += app.page_size;
                                app.refresh_data();
                            }
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!("{total_count} total"))
                                    .color(theme::TEXT_DIM)
                                    .size(11.0),
                            );
                        });
                    });
                });
            }

            ui.add_space(8.0);
        });
}

fn render_message_row(
    app: &mut BitmessageApp,
    ui: &mut egui::Ui,
    msg: &crate::storage::StoredMessage,
    is_unread: bool,
    folder: &str,
) {
    let msg_id = msg.id;
    let is_selected = app.selected_messages.contains(&msg_id);

    let bg = if is_selected {
        theme::BG_SELECTED
    } else if is_unread {
        theme::BG_SURFACE
    } else {
        Color32::TRANSPARENT
    };

    let frame = egui::Frame {
        fill: bg,
        inner_margin: egui::Margin::symmetric(16.0, 10.0),
        rounding: egui::Rounding::same(0.0),
        stroke: egui::Stroke::new(0.5, theme::BORDER),
        ..Default::default()
    };

    let response = frame
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                // Checkbox for multi-select
                let mut checked = is_selected;
                if ui.checkbox(&mut checked, "").changed() {
                    if checked {
                        app.selected_messages.insert(msg_id);
                    } else {
                        app.selected_messages.remove(&msg_id);
                    }
                }

                // Unread indicator
                if is_unread {
                    ui.label(RichText::new(icon::DOT).color(theme::ACCENT).size(8.0));
                }

                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        // Sender/recipient
                        let addr = if folder == "sent" {
                            &msg.to_address
                        } else {
                            &msg.from_address
                        };
                        let name = resolve_name(app, addr);

                        let text_style = if is_unread {
                            RichText::new(&name).strong().size(13.0)
                        } else {
                            RichText::new(&name)
                                .color(theme::TEXT_SECONDARY)
                                .size(13.0)
                        };
                        ui.label(text_style);

                        // Status badge for sent
                        if folder == "sent" {
                            let (status_text, color) = match msg.status.as_str() {
                                "ackreceived" => ("Acked", theme::SUCCESS),
                                "msgsent" => ("Sent", theme::ACCENT),
                                "doingmsgpow" => ("PoW...", theme::WARNING),
                                "doingpubkeypow" => ("PubKey...", theme::WARNING),
                                "awaitingpubkey" => ("Waiting", theme::TEXT_DIM),
                                "msgqueued" => ("Queued", theme::TEXT_DIM),
                                "broadcastsent" => ("Sent", theme::SUCCESS),
                                _ => (&msg.status as &str, theme::TEXT_DIM),
                            };
                            ui.label(
                                RichText::new(status_text).color(color).size(10.0),
                            );
                        }

                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                ui.label(
                                    RichText::new(theme::format_time(msg.created_at))
                                        .color(theme::TEXT_DIM)
                                        .size(11.0),
                                );
                            },
                        );
                    });

                    // Subject
                    let subject = if msg.subject.is_empty() {
                        "(no subject)"
                    } else {
                        &msg.subject
                    };
                    let subj_style = if is_unread {
                        RichText::new(subject).strong().size(12.0)
                    } else {
                        RichText::new(subject)
                            .color(theme::TEXT_SECONDARY)
                            .size(12.0)
                    };
                    ui.label(subj_style);

                    // Preview
                    let preview: String = msg
                        .body
                        .chars()
                        .take(100)
                        .map(|c| if c == '\n' { ' ' } else { c })
                        .collect();
                    ui.label(
                        RichText::new(preview)
                            .color(theme::TEXT_DIM)
                            .size(11.0),
                    );
                });
            });
        })
        .response;

    // Click on row (not on checkbox) opens the message
    if response.interact(egui::Sense::click()).clicked() {
        app.selected_msg_id = Some(msg_id);
        app.current_view = View::MessageDetail(msg_id);
    }
}

pub fn render_message_detail(app: &mut BitmessageApp, ui: &mut egui::Ui, msg_id: i64) {
    let msg = if let Ok(db) = app.db.lock() {
        db.get_message_by_id(msg_id).ok().flatten()
    } else {
        None
    };

    let Some(msg) = msg else {
        ui.label("Message not found");
        return;
    };

    // Mark as read
    if !msg.read {
        if let Ok(db) = app.db.lock() {
            let _ = db.mark_message_read(msg_id);
        }
        app.unread_inbox = app.unread_inbox.saturating_sub(1);
    }

    // Clear selection when viewing a message
    app.selected_messages.clear();

    // Header
    theme::header_frame().show(ui, |ui| {
        ui.horizontal(|ui| {
            if ui.add(theme::subtle_button(&theme::icon_text(icon::BACK, "Back"))).clicked() {
                app.current_view = match msg.folder.as_str() {
                    "sent" => View::Sent,
                    "trash" => View::Trash,
                    _ => View::Inbox,
                };
            }
            ui.add_space(8.0);
            let subject = if msg.subject.is_empty() {
                "(no subject)"
            } else {
                &msg.subject
            };
            ui.label(RichText::new(subject).size(16.0).strong());

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add(theme::subtle_button(&theme::icon_text(icon::DELETE, "Delete"))).clicked() {
                    if let Ok(db) = app.db.lock() {
                        if msg.folder == "trash" {
                            let _ = db.delete_message(msg_id);
                        } else {
                            let _ = db.trash_message(msg_id);
                        }
                    }
                    app.refresh_data();
                    app.current_view = match msg.folder.as_str() {
                        "sent" => View::Sent,
                        "trash" => View::Trash,
                        _ => View::Inbox,
                    };
                }

                // Undelete from trash
                if msg.folder == "trash" {
                    if ui.add(theme::subtle_button(&theme::icon_text(icon::BACK, "Restore"))).clicked() {
                        if let Ok(db) = app.db.lock() {
                            let _ = db.untrash_message(msg_id);
                        }
                        app.refresh_data();
                        app.current_view = View::Inbox;
                    }
                }

                if msg.folder != "sent" {
                    if ui.add(theme::subtle_button(&theme::icon_text(icon::REPLY, "Reply"))).clicked() {
                        app.compose.to = msg.from_address.clone();
                        app.compose.subject = format!("Re: {}", msg.subject);
                        app.compose.body.clear();
                        app.compose.is_broadcast = false;
                        app.current_view = View::Compose;
                    }
                }
            });
        });
    });

    // Message content
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
                // From / To
                ui.horizontal(|ui| {
                    ui.label(RichText::new("From:").color(theme::TEXT_DIM).size(12.0));
                    ui.label(
                        RichText::new(&msg.from_address)
                            .color(theme::ACCENT)
                            .size(12.0),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label(RichText::new("To:").color(theme::TEXT_DIM).size(12.0));
                    ui.label(
                        RichText::new(&msg.to_address)
                            .color(theme::ACCENT)
                            .size(12.0),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Date:").color(theme::TEXT_DIM).size(12.0));
                    ui.label(
                        RichText::new(theme::format_time(msg.created_at))
                            .color(theme::TEXT_SECONDARY)
                            .size(12.0),
                    );
                });

                if msg.folder == "sent" {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Status:").color(theme::TEXT_DIM).size(12.0));
                        ui.label(
                            RichText::new(&msg.status)
                                .color(theme::TEXT_SECONDARY)
                                .size(12.0),
                        );
                    });
                }

                ui.add_space(16.0);
                ui.separator();
                ui.add_space(12.0);

                // Body (with BBCode rendering)
                if bbcode::has_bbcode(&msg.body) {
                    bbcode::render_bbcode(ui, &msg.body);
                } else {
                    ui.label(
                        RichText::new(&msg.body)
                            .color(theme::TEXT_PRIMARY)
                            .size(13.0),
                    );
                }

                // Attachments
                let attachments = if let Ok(db) = app.db.lock() {
                    db.get_attachments_for_message(msg_id).unwrap_or_default()
                } else {
                    vec![]
                };

                if !attachments.is_empty() {
                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(theme::icon_text(icon::ATTACH, "Attachments"))
                            .size(13.0)
                            .strong()
                            .color(theme::TEXT_SECONDARY),
                    );
                    ui.add_space(4.0);

                    for att in &attachments {
                        egui::Frame {
                            fill: theme::BG_DARKEST,
                            inner_margin: egui::Margin::symmetric(12.0, 8.0),
                            rounding: egui::Rounding::same(6.0),
                            stroke: egui::Stroke::new(0.5, theme::BORDER),
                            ..Default::default()
                        }
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(icon::FILE)
                                        .size(16.0)
                                        .color(theme::ACCENT),
                                );
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(&att.filename)
                                            .size(13.0)
                                            .strong()
                                            .color(theme::TEXT_PRIMARY),
                                    );
                                    let size_str = format_file_size(att.total_size as u64);
                                    let status_str = match att.status.as_str() {
                                        "verified" => format!("{size_str} — Verified"),
                                        "failed" => format!("{size_str} — Hash mismatch!"),
                                        "incomplete" => format!(
                                            "{size_str} — Downloading {}/{}...",
                                            att.received_chunks, att.total_chunks
                                        ),
                                        other => format!("{size_str} — {other}"),
                                    };
                                    let status_color = match att.status.as_str() {
                                        "verified" => theme::SUCCESS,
                                        "failed" => theme::ERROR,
                                        _ => theme::TEXT_DIM,
                                    };
                                    ui.label(
                                        RichText::new(status_str)
                                            .size(11.0)
                                            .color(status_color),
                                    );

                                    if att.status == "incomplete" && att.total_chunks > 0 {
                                        let progress = att.received_chunks as f32 / att.total_chunks as f32;
                                        ui.add(egui::ProgressBar::new(progress).desired_width(200.0));
                                    }
                                });

                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    if att.status == "verified" {
                                        if ui.add(theme::subtle_button(
                                            &theme::icon_text(icon::DOWNLOAD, "Save")
                                        )).clicked() {
                                            if let Some(path) = rfd::FileDialog::new()
                                                .set_file_name(&att.filename)
                                                .save_file()
                                            {
                                                if let Ok(db) = app.db.lock() {
                                                    if let Some(data) = db.get_attachment_file_data(&att.transfer_id) {
                                                        let _ = std::fs::write(&path, &data);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                });
                            });
                        });
                        ui.add_space(4.0);
                    }
                }
            });
        });
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

/// Try to resolve address to a contact name or shorten it
fn resolve_name(app: &BitmessageApp, address: &str) -> String {
    if let Some(c) = app.contacts.iter().find(|c| c.address == address) {
        return c.label.clone();
    }
    if let Some(i) = app.identities.iter().find(|i| i.address == address) {
        return format!("{} (me)", i.label);
    }
    if let Some(ch) = app.channels.iter().find(|ch| ch.address == address) {
        return format!("[chan] {}", ch.label);
    }
    if address.len() > 16 {
        format!("{}...{}", &address[..10], &address[address.len() - 6..])
    } else {
        address.to_string()
    }
}
