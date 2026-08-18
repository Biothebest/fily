pub mod agent;
pub mod audit;
pub mod commands;
pub mod domain;
pub mod providers;
pub mod recovery;
pub mod storage;
pub mod vault;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }

            let state = commands::AppState::initialize(app.handle())
                .map_err(|error| format!("trusted core initialization failed: {}", error.code))?;
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::bootstrap,
            commands::list_accounts,
            commands::list_folders,
            commands::start_sync,
            commands::list_messages,
            commands::get_message,
            commands::search_messages,
            commands::create_draft,
            commands::list_plans,
            commands::approve_plan,
            commands::execute_plan,
            commands::undo_action,
            commands::list_audit,
            commands::disconnect_account,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Fily desktop application");
}
