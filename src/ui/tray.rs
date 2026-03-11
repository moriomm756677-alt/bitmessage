use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIcon, TrayIconBuilder, TrayIconEvent,
    Icon,
};

/// Menu item IDs
const ID_SHOW: &str = "show";
const ID_QUIT: &str = "quit";

/// Holds the tray icon and its state
pub struct AppTray {
    _tray_icon: TrayIcon,
    _show_item: MenuItem,
    _quit_item: MenuItem,
    last_unread: i64,
    last_connected: bool,
}

impl AppTray {
    /// Create a new system tray icon with menu
    pub fn new() -> Option<Self> {
        let show_item = MenuItem::with_id(ID_SHOW, "Show Bitmessage", true, None);
        let quit_item = MenuItem::with_id(ID_QUIT, "Quit", true, None);

        let menu = Menu::new();
        let _ = menu.append(&show_item);
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&quit_item);

        let icon = build_icon(0, false);

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Bitmessage — starting...")
            .with_icon(icon)
            .build();

        match tray_icon {
            Ok(ti) => Some(Self {
                _tray_icon: ti,
                _show_item: show_item,
                _quit_item: quit_item,
                last_unread: -1,
                last_connected: false,
            }),
            Err(e) => {
                log::warn!("Failed to create tray icon: {e}");
                None
            }
        }
    }

    /// Update the tray icon/tooltip based on current state.
    /// Returns true if icon was actually updated.
    pub fn update(&mut self, unread: i64, connected: bool) {
        if unread == self.last_unread && connected == self.last_connected {
            return;
        }
        self.last_unread = unread;
        self.last_connected = connected;

        let icon = build_icon(unread, connected);
        let _ = self._tray_icon.set_icon(Some(icon));

        let status = if connected { "connected" } else { "disconnected" };
        let tooltip = if unread > 0 {
            format!("Bitmessage — {unread} unread ({status})")
        } else {
            format!("Bitmessage — {status}")
        };
        let _ = self._tray_icon.set_tooltip(Some(&tooltip));
    }
}

/// Tray action returned to the app
pub enum TrayAction {
    Show,
    Quit,
    None,
}

/// Poll for tray events (call from update loop)
pub fn poll_tray_events() -> TrayAction {
    // Menu events
    if let Ok(event) = MenuEvent::receiver().try_recv() {
        match event.id().0.as_str() {
            ID_SHOW => return TrayAction::Show,
            ID_QUIT => return TrayAction::Quit,
            _ => {}
        }
    }

    // Tray icon click
    if let Ok(event) = TrayIconEvent::receiver().try_recv() {
        match event {
            TrayIconEvent::Click { button: tray_icon::MouseButton::Left, .. } => {
                return TrayAction::Show;
            }
            TrayIconEvent::DoubleClick { button: tray_icon::MouseButton::Left, .. } => {
                return TrayAction::Show;
            }
            _ => {}
        }
    }

    TrayAction::None
}

/// Build an RGBA icon (22x22) with connection status and unread badge
fn build_icon(unread: i64, connected: bool) -> Icon {
    const SIZE: usize = 44; // 44x44 for retina
    let mut rgba = vec![0u8; SIZE * SIZE * 4];

    // Draw envelope shape (centered, 32x24)
    let ox = 6; // offset x
    let oy = 10; // offset y
    let w = 32;
    let h = 24;

    let base_color: [u8; 4] = if connected {
        [200, 210, 220, 255] // light blue-gray when connected
    } else {
        [120, 120, 130, 255] // dim gray when disconnected
    };

    // Fill envelope body
    for y in oy..oy + h {
        for x in ox..ox + w {
            set_pixel(&mut rgba, SIZE, x, y, base_color);
        }
    }

    // Darker inner area (envelope opening)
    let inner_color: [u8; 4] = if connected {
        [45, 52, 65, 255]
    } else {
        [60, 60, 65, 255]
    };
    for y in (oy + 2)..(oy + h - 2) {
        for x in (ox + 2)..(ox + w - 2) {
            set_pixel(&mut rgba, SIZE, x, y, inner_color);
        }
    }

    // Draw V-shape (envelope flap) with lines
    let _mid_x = ox + w / 2;
    let flap_bottom = oy + h / 2 + 2;
    for i in 0..w / 2 {
        let lx = ox + i;
        let rx = ox + w - 1 - i;
        let y = oy + (i * (flap_bottom - oy)) / (w / 2);
        if y < SIZE && lx < SIZE && rx < SIZE {
            set_pixel(&mut rgba, SIZE, lx, y, base_color);
            set_pixel(&mut rgba, SIZE, rx, y, base_color);
            // Thicker lines
            if y + 1 < oy + h {
                set_pixel(&mut rgba, SIZE, lx, y + 1, base_color);
                set_pixel(&mut rgba, SIZE, rx, y + 1, base_color);
            }
        }
    }

    // Draw unread badge (red circle with number) in top-right
    if unread > 0 {
        let badge_text = if unread > 99 { "99+".to_string() } else { unread.to_string() };
        let badge_r = if badge_text.len() > 2 { 10 } else if badge_text.len() > 1 { 9 } else { 8 };
        let bcx = SIZE as i32 - badge_r as i32 - 1;
        let bcy = badge_r as i32 + 1;

        // Draw red circle
        for y in 0..SIZE {
            for x in 0..SIZE {
                let dx = x as i32 - bcx;
                let dy = y as i32 - bcy;
                let dist_sq = dx * dx + dy * dy;
                let r_sq = (badge_r * badge_r) as i32;
                if dist_sq <= r_sq {
                    set_pixel(&mut rgba, SIZE, x, y, [220, 50, 50, 255]);
                }
            }
        }

        // Draw digits
        let chars: Vec<char> = badge_text.chars().collect();
        let total_w = chars.len() as i32 * 5 + (chars.len() as i32 - 1); // 5px wide + 1px gap
        let start_x = bcx - total_w / 2;
        for (i, ch) in chars.iter().enumerate() {
            let cx = start_x + i as i32 * 6;
            let cy = bcy - 3;
            draw_digit(&mut rgba, SIZE, cx, cy, *ch);
        }
    }

    // Small connection indicator dot (bottom-left)
    let dot_color: [u8; 4] = if connected {
        [80, 200, 80, 255] // green
    } else {
        [200, 80, 80, 255] // red
    };
    let dcx = 8i32;
    let dcy = SIZE as i32 - 8;
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as i32 - dcx;
            let dy = y as i32 - dcy;
            if dx * dx + dy * dy <= 12 {
                set_pixel(&mut rgba, SIZE, x, y, dot_color);
            }
        }
    }

    Icon::from_rgba(rgba, SIZE as u32, SIZE as u32).expect("valid icon")
}

fn set_pixel(rgba: &mut [u8], size: usize, x: usize, y: usize, color: [u8; 4]) {
    if x < size && y < size {
        let idx = (y * size + x) * 4;
        rgba[idx..idx + 4].copy_from_slice(&color);
    }
}

/// Draw a tiny 5x7 digit character
fn draw_digit(rgba: &mut [u8], size: usize, x: i32, y: i32, ch: char) {
    let bitmap: &[u8; 7] = match ch {
        '0' => &[0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110],
        '1' => &[0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110],
        '2' => &[0b01110, 0b10001, 0b00001, 0b00110, 0b01000, 0b10000, 0b11111],
        '3' => &[0b01110, 0b10001, 0b00001, 0b00110, 0b00001, 0b10001, 0b01110],
        '4' => &[0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010],
        '5' => &[0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110],
        '6' => &[0b01110, 0b10000, 0b11110, 0b10001, 0b10001, 0b10001, 0b01110],
        '7' => &[0b11111, 0b00001, 0b00010, 0b00100, 0b00100, 0b00100, 0b00100],
        '8' => &[0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110],
        '9' => &[0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00001, 0b01110],
        '+' => &[0b00000, 0b00100, 0b00100, 0b11111, 0b00100, 0b00100, 0b00000],
        _ => &[0b00000; 7],
    };

    for row in 0..7 {
        for col in 0..5 {
            if bitmap[row] & (1 << (4 - col)) != 0 {
                let px = x + col;
                let py = y + row as i32;
                if px >= 0 && py >= 0 {
                    set_pixel(rgba, size, px as usize, py as usize, [255, 255, 255, 255]);
                }
            }
        }
    }
}
