use eframe::egui::{self, Color32, RichText};
use super::theme;

// ============================================================================
// TAG TYPES
// ============================================================================

enum Tag {
    BoldOpen, BoldClose,
    ItalicOpen, ItalicClose,
    UnderlineOpen, UnderlineClose,
    StrikeOpen, StrikeClose,
    CodeOpen, CodeClose,
    QuoteOpen, QuoteClose,
    ColorOpen(Color32), ColorClose,
    SizeOpen(f32), SizeClose,
    UrlOpen, UrlClose,
}

// ============================================================================
// STYLED SPAN
// ============================================================================

struct Span {
    text: String,
    bold: bool,
    italic: bool,
    underline: bool,
    strikethrough: bool,
    color: Color32,
    size: f32,
    monospace: bool,
    quote_level: u32,
}

// ============================================================================
// TAG MATCHING
// ============================================================================

fn match_tag(text: &str) -> Option<(Tag, usize)> {
    // text starts with '['
    let end = text.find(']')?;
    let inner = &text[1..end];
    let tag_len = end + 1; // includes the ']'

    let lower = inner.to_ascii_lowercase();

    match lower.as_str() {
        "b" => Some((Tag::BoldOpen, tag_len)),
        "/b" => Some((Tag::BoldClose, tag_len)),
        "i" => Some((Tag::ItalicOpen, tag_len)),
        "/i" => Some((Tag::ItalicClose, tag_len)),
        "u" => Some((Tag::UnderlineOpen, tag_len)),
        "/u" => Some((Tag::UnderlineClose, tag_len)),
        "s" => Some((Tag::StrikeOpen, tag_len)),
        "/s" => Some((Tag::StrikeClose, tag_len)),
        "code" => Some((Tag::CodeOpen, tag_len)),
        "/code" => Some((Tag::CodeClose, tag_len)),
        "quote" => Some((Tag::QuoteOpen, tag_len)),
        "/quote" => Some((Tag::QuoteClose, tag_len)),
        "/color" => Some((Tag::ColorClose, tag_len)),
        "/size" => Some((Tag::SizeClose, tag_len)),
        "url" => Some((Tag::UrlOpen, tag_len)),
        "/url" => Some((Tag::UrlClose, tag_len)),
        _ => {
            if let Some(val) = lower.strip_prefix("color=") {
                let color = parse_color(val)?;
                Some((Tag::ColorOpen(color), tag_len))
            } else if let Some(val) = lower.strip_prefix("size=") {
                let size: f32 = val.parse().ok()?;
                Some((Tag::SizeOpen(size.clamp(8.0, 30.0)), tag_len))
            } else if lower.starts_with("url=") {
                Some((Tag::UrlOpen, tag_len))
            } else {
                None
            }
        }
    }
}

fn parse_color(s: &str) -> Option<Color32> {
    if let Some(hex) = s.strip_prefix('#') {
        if hex.len() == 6 {
            let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
            let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
            let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
            return Some(Color32::from_rgb(r, g, b));
        } else if hex.len() == 3 {
            let r = u8::from_str_radix(&hex[0..1], 16).ok()? * 17;
            let g = u8::from_str_radix(&hex[1..2], 16).ok()? * 17;
            let b = u8::from_str_radix(&hex[2..3], 16).ok()? * 17;
            return Some(Color32::from_rgb(r, g, b));
        }
    }
    match s {
        "red" => Some(Color32::from_rgb(220, 60, 60)),
        "green" => Some(Color32::from_rgb(60, 180, 75)),
        "blue" => Some(Color32::from_rgb(70, 130, 220)),
        "yellow" => Some(Color32::from_rgb(230, 200, 50)),
        "orange" => Some(Color32::from_rgb(230, 150, 40)),
        "purple" => Some(Color32::from_rgb(160, 90, 220)),
        "white" => Some(Color32::from_rgb(240, 240, 240)),
        "black" => Some(Color32::from_rgb(30, 30, 30)),
        "gray" | "grey" => Some(Color32::from_rgb(140, 140, 140)),
        "cyan" => Some(Color32::from_rgb(60, 200, 210)),
        "magenta" => Some(Color32::from_rgb(200, 60, 180)),
        "pink" => Some(Color32::from_rgb(230, 130, 170)),
        _ => None,
    }
}

// ============================================================================
// PARSER
// ============================================================================

fn parse(input: &str) -> Vec<Span> {
    let mut spans: Vec<Span> = Vec::new();
    let bytes = input.as_bytes();
    let len = input.len();

    // Style state
    let mut bold = false;
    let mut italic = false;
    let mut underline = false;
    let mut strikethrough = false;
    let mut color_stack: Vec<Color32> = vec![];
    let mut size_stack: Vec<f32> = vec![];
    let mut monospace = false;
    let mut quote_level: u32 = 0;
    let mut is_url = false;

    let mut current_text = String::new();
    let mut i = 0;

    while i < len {
        if bytes[i] == b'[' {
            if let Some((tag, tag_byte_len)) = match_tag(&input[i..]) {
                // Flush accumulated text
                if !current_text.is_empty() {
                    spans.push(Span {
                        text: std::mem::take(&mut current_text),
                        bold,
                        italic,
                        underline: underline || is_url,
                        strikethrough,
                        color: if is_url {
                            theme::ACCENT
                        } else {
                            color_stack.last().copied().unwrap_or(theme::TEXT_PRIMARY)
                        },
                        size: size_stack.last().copied().unwrap_or(13.0),
                        monospace,
                        quote_level,
                    });
                }

                match tag {
                    Tag::BoldOpen => bold = true,
                    Tag::BoldClose => bold = false,
                    Tag::ItalicOpen => italic = true,
                    Tag::ItalicClose => italic = false,
                    Tag::UnderlineOpen => underline = true,
                    Tag::UnderlineClose => underline = false,
                    Tag::StrikeOpen => strikethrough = true,
                    Tag::StrikeClose => strikethrough = false,
                    Tag::CodeOpen => monospace = true,
                    Tag::CodeClose => monospace = false,
                    Tag::QuoteOpen => {
                        quote_level += 1;
                        color_stack.push(theme::TEXT_SECONDARY);
                    }
                    Tag::QuoteClose => {
                        quote_level = quote_level.saturating_sub(1);
                        color_stack.pop();
                    }
                    Tag::ColorOpen(c) => color_stack.push(c),
                    Tag::ColorClose => { color_stack.pop(); }
                    Tag::SizeOpen(s) => size_stack.push(s),
                    Tag::SizeClose => { size_stack.pop(); }
                    Tag::UrlOpen => is_url = true,
                    Tag::UrlClose => is_url = false,
                }

                i += tag_byte_len;
                continue;
            }
        }

        let ch = input[i..].chars().next().unwrap();
        current_text.push(ch);
        i += ch.len_utf8();
    }

    // Final flush
    if !current_text.is_empty() {
        spans.push(Span {
            text: current_text,
            bold,
            italic,
            underline: underline || is_url,
            strikethrough,
            color: if is_url {
                theme::ACCENT
            } else {
                color_stack.last().copied().unwrap_or(theme::TEXT_PRIMARY)
            },
            size: size_stack.last().copied().unwrap_or(13.0),
            monospace,
            quote_level,
        });
    }

    spans
}

// ============================================================================
// RENDERER  (LayoutJob — single widget, proper inline flow)
// ============================================================================

/// Render BBCode-formatted text into the UI
pub fn render_bbcode(ui: &mut egui::Ui, text: &str) {
    let spans = parse(text);
    if spans.is_empty() {
        return;
    }

    let mut job = egui::text::LayoutJob::default();
    job.wrap.max_width = ui.available_width();

    for span in &spans {
        let family = if span.monospace {
            egui::FontFamily::Monospace
        } else {
            egui::FontFamily::Proportional
        };

        // Bold: bump size +1 and brighten color for visible difference
        let size = if span.bold { span.size + 1.0 } else { span.size };
        let color = if span.monospace {
            theme::WARNING
        } else if span.bold && span.color == theme::TEXT_PRIMARY {
            Color32::from_rgb(245, 248, 255)
        } else {
            span.color
        };

        let format = egui::TextFormat {
            font_id: egui::FontId::new(size, family),
            color,
            italics: span.italic,
            underline: if span.underline {
                egui::Stroke::new(1.0, color)
            } else {
                egui::Stroke::NONE
            },
            strikethrough: if span.strikethrough {
                egui::Stroke::new(1.0, color)
            } else {
                egui::Stroke::NONE
            },
            background: if span.monospace {
                theme::BG_DARKEST
            } else {
                Color32::TRANSPARENT
            },
            ..Default::default()
        };

        if span.quote_level > 0 {
            // Prefix each line with quote marker
            for (li, line) in span.text.split('\n').enumerate() {
                if li > 0 {
                    job.append("\n", 0.0, format.clone());
                }
                let indent = "  ".repeat(span.quote_level as usize);
                // Quote bar in accent color
                let bar_fmt = egui::TextFormat {
                    font_id: egui::FontId::new(size, egui::FontFamily::Proportional),
                    color: theme::ACCENT_MUTED,
                    ..Default::default()
                };
                job.append(&format!("{}▎ ", indent), 0.0, bar_fmt);
                job.append(line, 0.0, format.clone());
            }
        } else {
            job.append(&span.text, 0.0, format);
        }
    }

    ui.label(job);
}

// ============================================================================
// TOOLBAR (for compose view)
// ============================================================================

/// Render BBCode formatting toolbar. Returns true if text was modified.
pub fn bbcode_toolbar(ui: &mut egui::Ui, text: &mut String, cursor: &mut Option<(usize, usize)>) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 3.0;

        if toolbar_btn(ui, "B", true, false) { wrap_tag(text, cursor, "b"); }
        if toolbar_btn(ui, "I", false, true) { wrap_tag(text, cursor, "i"); }
        if toolbar_btn_underline(ui, "U") { wrap_tag(text, cursor, "u"); }
        if toolbar_btn_strike(ui, "S") { wrap_tag(text, cursor, "s"); }

        ui.add_space(4.0);
        ui.label(RichText::new("│").size(14.0).color(theme::BORDER_LIGHT));
        ui.add_space(4.0);

        if toolbar_btn_colored(ui, "Color", theme::ERROR) {
            wrap_tag_param(text, cursor, "color", "red");
        }
        if toolbar_btn(ui, "Size", false, false) {
            wrap_tag_param(text, cursor, "size", "16");
        }

        ui.add_space(4.0);
        ui.label(RichText::new("│").size(14.0).color(theme::BORDER_LIGHT));
        ui.add_space(4.0);

        if toolbar_btn_colored(ui, "URL", theme::ACCENT) { wrap_tag(text, cursor, "url"); }
        if toolbar_btn(ui, "Quote", false, false) { wrap_tag(text, cursor, "quote"); }
        if toolbar_btn(ui, "Code", false, false) { wrap_tag(text, cursor, "code"); }
    });
}

fn toolbar_btn(ui: &mut egui::Ui, label: &str, bold: bool, italic: bool) -> bool {
    let mut rt = RichText::new(label).size(12.0).color(theme::TEXT_SECONDARY);
    if bold { rt = rt.strong(); }
    if italic { rt = rt.italics(); }
    ui.add(
        egui::Button::new(rt)
            .fill(theme::BG_SURFACE)
            .stroke(egui::Stroke::new(0.5, theme::BORDER_LIGHT))
            .rounding(4.0)
            .min_size(egui::vec2(26.0, 22.0)),
    )
    .clicked()
}

fn toolbar_btn_underline(ui: &mut egui::Ui, label: &str) -> bool {
    let rt = RichText::new(label).size(12.0).color(theme::TEXT_SECONDARY).underline();
    ui.add(
        egui::Button::new(rt)
            .fill(theme::BG_SURFACE)
            .stroke(egui::Stroke::new(0.5, theme::BORDER_LIGHT))
            .rounding(4.0)
            .min_size(egui::vec2(26.0, 22.0)),
    )
    .clicked()
}

fn toolbar_btn_strike(ui: &mut egui::Ui, label: &str) -> bool {
    let rt = RichText::new(label).size(12.0).color(theme::TEXT_SECONDARY).strikethrough();
    ui.add(
        egui::Button::new(rt)
            .fill(theme::BG_SURFACE)
            .stroke(egui::Stroke::new(0.5, theme::BORDER_LIGHT))
            .rounding(4.0)
            .min_size(egui::vec2(26.0, 22.0)),
    )
    .clicked()
}

fn toolbar_btn_colored(ui: &mut egui::Ui, label: &str, color: Color32) -> bool {
    let rt = RichText::new(label).size(12.0).color(color);
    ui.add(
        egui::Button::new(rt)
            .fill(theme::BG_SURFACE)
            .stroke(egui::Stroke::new(0.5, theme::BORDER_LIGHT))
            .rounding(4.0)
            .min_size(egui::vec2(26.0, 22.0)),
    )
    .clicked()
}

// ============================================================================
// TAG INSERTION HELPERS
// ============================================================================

fn wrap_tag(text: &mut String, cursor: &mut Option<(usize, usize)>, tag: &str) {
    let open = format!("[{tag}]");
    let close = format!("[/{tag}]");
    insert_around(text, cursor, &open, &close);
}

fn wrap_tag_param(text: &mut String, cursor: &mut Option<(usize, usize)>, tag: &str, param: &str) {
    let open = format!("[{tag}={param}]");
    let close = format!("[/{tag}]");
    insert_around(text, cursor, &open, &close);
}

fn insert_around(text: &mut String, cursor: &mut Option<(usize, usize)>, open: &str, close: &str) {
    if let Some((start, end)) = *cursor {
        let byte_start = char_to_byte(text, start);
        let byte_end = char_to_byte(text, end);
        text.insert_str(byte_end, close);
        text.insert_str(byte_start, open);
        let open_chars = open.chars().count();
        *cursor = Some((start + open_chars, end + open_chars));
    } else {
        text.push_str(open);
        text.push_str(close);
    }
}

fn char_to_byte(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map(|(b, _)| b)
        .unwrap_or(s.len())
}

/// Check if text contains any BBCode tags
pub fn has_bbcode(text: &str) -> bool {
    let tags = ["[b]", "[i]", "[u]", "[s]", "[code]", "[quote]", "[url",
                "[color=", "[size=", "[/b]", "[/i]", "[/u]", "[/s]"];
    let lower = text.to_ascii_lowercase();
    tags.iter().any(|t| lower.contains(t))
}
