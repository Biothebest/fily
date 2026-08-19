pub mod agent;
pub mod audit;
pub mod autonomy;
pub mod commands;
pub mod domain;
pub mod local_files;
pub mod migration;
mod native_credentials;
pub mod ollama;
pub mod providers;
pub mod recovery;
pub mod steward;
pub mod storage;
pub mod sync;
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
            app.state::<commands::AppState>()
                .scheduler_tick()
                .map_err(|error| {
                    format!("local scheduler initialization failed: {}", error.code)
                })?;
            let scheduler_app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60 * 60)).await;
                    let _ = scheduler_app.state::<commands::AppState>().scheduler_tick();
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::bootstrap,
            commands::list_accounts,
            commands::begin_account_connection,
            commands::account_connection_status,
            commands::complete_account_connection,
            commands::list_folders,
            commands::start_sync,
            commands::list_messages,
            commands::get_message,
            commands::search_messages,
            commands::discover_ollama_models,
            commands::ask_records,
            commands::ask_agent,
            commands::list_review_queue,
            commands::decide_review_item,
            commands::undo_review_item,
            commands::list_rules,
            commands::preview_rule_change,
            commands::confirm_rule_change,
            commands::list_archives,
            commands::get_daily_report,
            commands::create_draft,
            commands::update_draft,
            commands::list_drafts,
            commands::delete_draft,
            commands::create_reply_draft,
            commands::create_send_preview,
            commands::execute_send,
            commands::list_plans,
            commands::approve_plan,
            commands::execute_plan,
            commands::undo_action,
            commands::list_audit,
            commands::disconnect_account,
            commands::legacy_migration_status,
            commands::migrate_legacy,
            local_files::pick_folder_grant,
            local_files::list_folder_grants,
            local_files::revoke_folder_grant,
            local_files::rescan_folder_grant,
            local_files::get_file_record,
            local_files::search_files,
            local_files::list_file_relations,
            local_files::create_file_action_plan,
            local_files::approve_file_action_plan,
            local_files::execute_file_action_plan,
            local_files::undo_file_action,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run Fily desktop application");
}
