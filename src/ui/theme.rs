use eframe::egui::{self, Color32, Rounding, Stroke, Margin};

// ============================================================================
// COLOR PALETTE - Refined dark theme with blue accent
// ============================================================================

// Backgrounds (warm-neutral dark, not pure black)
pub const BG_DARKEST: Color32 = Color32::from_rgb(16, 18, 22);
pub const BG_DARK: Color32 = Color32::from_rgb(22, 24, 30);
pub const BG_PANEL: Color32 = Color32::from_rgb(30, 33, 40);
pub const BG_SURFACE: Color32 = Color32::from_rgb(40, 43, 52);
pub const BG_HOVER: Color32 = Color32::from_rgb(50, 54, 64);
pub const BG_SELECTED: Color32 = Color32::from_rgb(45, 55, 80);

// Accent - soft blue
pub const ACCENT: Color32 = Color32::from_rgb(100, 140, 220);
pub const ACCENT_HOVER: Color32 = Color32::from_rgb(130, 165, 240);
pub const ACCENT_MUTED: Color32 = Color32::from_rgb(70, 90, 140);
pub const ACCENT_DIM: Color32 = Color32::from_rgb(50, 65, 100);

// Semantic
pub const SUCCESS: Color32 = Color32::from_rgb(75, 190, 110);
pub const WARNING: Color32 = Color32::from_rgb(230, 180, 60);
pub const ERROR: Color32 = Color32::from_rgb(210, 80, 80);

// Text
pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(220, 224, 232);
pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(150, 155, 170);
pub const TEXT_DIM: Color32 = Color32::from_rgb(90, 95, 115);
pub const TEXT_ON_ACCENT: Color32 = Color32::from_rgb(255, 255, 255);

// Borders
pub const BORDER: Color32 = Color32::from_rgb(42, 46, 56);
pub const BORDER_LIGHT: Color32 = Color32::from_rgb(55, 60, 72);

// ============================================================================
// ICONS - Using only reliable Unicode + ASCII that render everywhere
// ============================================================================

pub mod icon {
    // Navigation & Actions - ASCII-safe symbols
    pub const COMPOSE: &str = "\u{270F}";  // Pencil (✏)
    pub const INBOX: &str = "\u{25A3}";    // White square with rounded corners
    pub const SENT: &str = "\u{25B3}";     // Triangle up (△)
    pub const TRASH: &str = "\u{2212}";    // Minus sign (−)
    pub const CONTACTS: &str = "\u{25CB}"; // Circle outline (○)
    pub const SUBS: &str = "\u{25C9}";     // Fisheye (◉)
    pub const CHANNELS: &str = "#";
    pub const IDENTITY: &str = "\u{25C6}"; // Diamond filled (◆)
    pub const NETWORK: &str = "\u{25CE}";  // Bullseye (◎)
    pub const SETTINGS: &str = "\u{2261}"; // Triple bar (≡)
    pub const SEARCH: &str = "\u{25B7}";   // Triangle right (▷)
    pub const BACK: &str = "\u{2190}";     // Left arrow (←)
    pub const DELETE: &str = "\u{00D7}";   // Multiplication sign (×) - Latin-1, always works
    pub const REPLY: &str = "\u{21B5}";    // Downwards arrow with corner (↵)
    pub const SEND: &str = "\u{25B6}";     // Black right triangle (▶)
    pub const ADD: &str = "+";
    pub const COPY: &str = "\u{25A1}";     // White square (□)
    pub const KEY: &str = "\u{25C6}";      // Diamond filled (◆)
    pub const CHECK: &str = "\u{2022}";    // Bullet (•) - always renders
    pub const STAR: &str = "\u{2605}";     // Black star (★)
    pub const DOT: &str = "\u{25CF}";      // Black circle (●)
    pub const LOCK: &str = "\u{25A0}";     // Black square (■)
    pub const EXPORT: &str = "\u{21E1}";   // Upwards dashed arrow (⇡)
    pub const RESTORE: &str = "\u{21BA}";  // Counterclockwise arrow (↺)
    pub const ATTACH: &str = "\u{25C7}";   // Diamond outline (◇)
    pub const DOWNLOAD: &str = "\u{2193}"; // Downwards arrow (↓)
    pub const FILE: &str = "\u{25A1}";     // White square (□)
}

/// Load system fonts with broad Unicode coverage
fn load_symbol_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // Load multiple symbol fonts as fallback chain
    // Priority: Arial Unicode (best coverage) > Apple Symbols > others
    let font_entries: &[(&str, &str)] = &[
        // macOS - best coverage first
        ("arial_unicode", "/System/Library/Fonts/Supplemental/Arial Unicode.ttf"),
        ("apple_symbols", "/System/Library/Fonts/Apple Symbols.ttf"),
        // Linux
        ("dejavu", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        ("dejavu_alt", "/usr/share/fonts/TTF/DejaVuSans.ttf"),
        ("noto_symbols", "/usr/share/fonts/truetype/noto/NotoSansSymbols2-Regular.ttf"),
    ];

    let mut loaded_any = false;
    for (name, path) in font_entries {
        if let Ok(data) = std::fs::read(path) {
            let font_name = name.to_string();
            fonts.font_data.insert(
                font_name.clone(),
                egui::FontData::from_owned(data),
            );
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                family.push(font_name.clone());
            }
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                family.push(font_name);
            }
            loaded_any = true;
        }
    }

    if loaded_any {
        ctx.set_fonts(fonts);
    }
}

pub fn apply_theme(ctx: &egui::Context) {
    load_symbol_fonts(ctx);

    let mut visuals = egui::Visuals::dark();

    visuals.panel_fill = BG_DARK;
    visuals.window_fill = BG_PANEL;
    visuals.faint_bg_color = BG_SURFACE;
    visuals.extreme_bg_color = BG_DARKEST;

    // Widgets - noninteractive (labels, separators)
    visuals.widgets.noninteractive.bg_fill = BG_SURFACE;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_SECONDARY);
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(0.5, BORDER);
    visuals.widgets.noninteractive.rounding = Rounding::same(6.0);

    // Widgets - inactive (buttons at rest)
    visuals.widgets.inactive.bg_fill = BG_SURFACE;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.inactive.bg_stroke = Stroke::new(0.5, BORDER_LIGHT);
    visuals.widgets.inactive.rounding = Rounding::same(6.0);

    // Widgets - hovered
    visuals.widgets.hovered.bg_fill = BG_HOVER;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT_MUTED);
    visuals.widgets.hovered.rounding = Rounding::same(6.0);

    // Widgets - active (pressed)
    visuals.widgets.active.bg_fill = ACCENT;
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, TEXT_ON_ACCENT);
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT_HOVER);
    visuals.widgets.active.rounding = Rounding::same(6.0);

    // Widgets - open (dropdown etc)
    visuals.widgets.open.bg_fill = BG_HOVER;
    visuals.widgets.open.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.open.bg_stroke = Stroke::new(1.0, ACCENT_MUTED);
    visuals.widgets.open.rounding = Rounding::same(6.0);

    // Selection
    visuals.selection.bg_fill = ACCENT_DIM;
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);

    // Windows
    visuals.window_rounding = Rounding::same(10.0);
    visuals.window_stroke = Stroke::new(1.0, BORDER_LIGHT);
    visuals.window_shadow = egui::epaint::Shadow {
        offset: egui::vec2(0.0, 4.0),
        blur: 16.0,
        spread: 0.0,
        color: Color32::from_black_alpha(80),
    };

    visuals.override_text_color = Some(TEXT_PRIMARY);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = egui::vec2(8.0, 5.0);
    style.spacing.button_padding = egui::vec2(14.0, 6.0);
    style.spacing.window_margin = Margin::same(16.0);
    ctx.set_style(style);
}

// ============================================================================
// FRAMES
// ============================================================================

/// Card frame for list items
pub fn card_frame() -> egui::Frame {
    egui::Frame {
        fill: BG_SURFACE,
        rounding: Rounding::same(10.0),
        inner_margin: Margin::same(14.0),
        outer_margin: Margin::symmetric(16.0, 3.0),
        stroke: Stroke::new(0.5, BORDER_LIGHT),
        shadow: egui::epaint::Shadow::NONE,
    }
}

/// Sidebar frame
pub fn sidebar_frame() -> egui::Frame {
    egui::Frame {
        fill: BG_PANEL,
        inner_margin: Margin::same(12.0),
        stroke: Stroke::new(0.5, BORDER),
        ..Default::default()
    }
}

/// Header bar frame
pub fn header_frame() -> egui::Frame {
    egui::Frame {
        fill: BG_PANEL,
        inner_margin: Margin::symmetric(20.0, 12.0),
        stroke: Stroke::new(0.5, BORDER),
        ..Default::default()
    }
}

// ============================================================================
// BUTTONS
// ============================================================================

/// Primary action button (accent color)
pub fn accent_button(text: &str) -> egui::Button<'_> {
    egui::Button::new(
        egui::RichText::new(text)
            .color(TEXT_ON_ACCENT)
            .strong()
            .size(13.0),
    )
    .fill(ACCENT)
    .rounding(8.0)
    .min_size(egui::vec2(0.0, 34.0))
}

/// Secondary / subtle button (outline style)
pub fn subtle_button(text: &str) -> egui::Button<'_> {
    egui::Button::new(
        egui::RichText::new(text)
            .color(TEXT_SECONDARY)
            .size(12.0),
    )
    .fill(Color32::TRANSPARENT)
    .stroke(Stroke::new(1.0, BORDER_LIGHT))
    .rounding(6.0)
    .min_size(egui::vec2(0.0, 30.0))
}

/// Danger button (for destructive actions)
pub fn danger_button(text: &str) -> egui::Button<'_> {
    egui::Button::new(
        egui::RichText::new(text)
            .color(ERROR)
            .size(12.0),
    )
    .fill(Color32::TRANSPARENT)
    .stroke(Stroke::new(1.0, Color32::from_rgb(100, 45, 45)))
    .rounding(6.0)
    .min_size(egui::vec2(0.0, 30.0))
}

// ============================================================================
// COMPONENTS
// ============================================================================

/// Badge for unread count
pub fn unread_badge(ui: &mut egui::Ui, count: i64) {
    if count > 0 {
        let text = if count > 99 {
            "99+".to_string()
        } else {
            count.to_string()
        };
        let galley = ui.painter().layout_no_wrap(
            text.clone(),
            egui::FontId::proportional(10.0),
            TEXT_ON_ACCENT,
        );
        let desired_size = egui::vec2(galley.size().x.max(16.0) + 10.0, 18.0);
        let (rect, _) = ui.allocate_exact_size(desired_size, egui::Sense::hover());
        ui.painter()
            .rect_filled(rect, Rounding::same(9.0), ACCENT);
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            text,
            egui::FontId::proportional(10.0),
            TEXT_ON_ACCENT,
        );
    }
}

/// Section header in sidebar
pub fn section_header(ui: &mut egui::Ui, text: &str) {
    ui.add_space(14.0);
    ui.label(
        egui::RichText::new(text.to_uppercase())
            .color(TEXT_DIM)
            .size(10.0)
            .strong(),
    );
    ui.add_space(4.0);
}

/// Format a unix timestamp
pub fn format_time(timestamp: i64) -> String {
    use chrono::{DateTime, Local, Utc};
    let dt = DateTime::<Utc>::from_timestamp(timestamp, 0)
        .unwrap_or_default()
        .with_timezone(&Local);
    let now = Local::now();

    if dt.date_naive() == now.date_naive() {
        dt.format("%H:%M").to_string()
    } else if (now - dt).num_days() < 7 {
        dt.format("%a %H:%M").to_string()
    } else {
        dt.format("%d %b %Y").to_string()
    }
}

/// Icon with text helper
pub fn icon_text(ico: &str, label: &str) -> String {
    format!("{ico}  {label}")
}
