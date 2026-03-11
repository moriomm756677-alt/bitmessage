#[allow(dead_code)]
mod protocol;
#[allow(dead_code)]
mod crypto;
mod network;
mod storage;
mod ui;

use std::sync::{mpsc, Arc, Mutex};

fn main() {
    env_logger::init();

    let db = Arc::new(Mutex::new(
        storage::Database::new().expect("Failed to initialize database"),
    ));

    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (event_tx, event_rx) = mpsc::channel();

    let runtime = Arc::new(
        tokio::runtime::Runtime::new().expect("Failed to create tokio runtime"),
    );

    let net_db = db.clone();
    runtime.spawn(async move {
        network::run(cmd_rx, event_tx, net_db).await;
    });

    // Create tray icon BEFORE eframe (must be on main thread, before event loop)
    let tray = ui::tray::AppTray::new();

    // Load window icon from embedded PNG
    let icon_data = include_bytes!("logo_icon.png");
    let icon_image = image::load_from_memory(icon_data).expect("Failed to load icon PNG");
    let icon_rgba = icon_image.to_rgba8();
    let (icon_w, icon_h) = icon_rgba.dimensions();
    let viewport = eframe::egui::ViewportBuilder::default()
        .with_inner_size([1200.0, 800.0])
        .with_min_inner_size([800.0, 600.0])
        .with_icon(eframe::egui::IconData {
            rgba: icon_rgba.into_raw(),
            width: icon_w,
            height: icon_h,
        });

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    let rt = runtime.clone();
    if let Err(e) = eframe::run_native(
        "Bitmessage",
        options,
        Box::new(move |cc| {
            ui::theme::apply_theme(&cc.egui_ctx);
            Ok(Box::new(ui::app::BitmessageApp::new(
                db, cmd_tx, event_rx, rt, tray,
            )))
        }),
    ) {
        eprintln!("Application error: {e}");
    }
}
