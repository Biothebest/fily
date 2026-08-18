use std::{fs, sync::Mutex};

use tauri::{Manager, RunEvent};
use tauri_plugin_shell::{process::CommandChild, ShellExt};

struct BackendProcess(Mutex<Option<CommandChild>>);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let application = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            let library = app.path().home_dir()?.join("FilyLibrary");
            fs::create_dir_all(&library)?;
            let library = library
                .to_str()
                .ok_or("Fily data directory is not valid UTF-8")?;
            let arguments = vec![
                "serve".to_owned(),
                library.to_owned(),
                "--host".to_owned(),
                "127.0.0.1".to_owned(),
                "--port".to_owned(),
                "8765".to_owned(),
                "--parent-pid".to_owned(),
                std::process::id().to_string(),
            ];
            let sidecar = app.shell().sidecar("fily-backend")?.args(arguments);
            let (_events, child) = sidecar.spawn()?;
            app.manage(BackendProcess(Mutex::new(Some(child))));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build Fily desktop application");

    application.run(|handle, event| {
        if matches!(event, RunEvent::Exit | RunEvent::ExitRequested { .. }) {
            if let Some(process) = handle.try_state::<BackendProcess>() {
                if let Ok(mut child) = process.0.lock() {
                    if let Some(child) = child.take() {
                        let _ = child.kill();
                    }
                }
            }
        }
    });
}
