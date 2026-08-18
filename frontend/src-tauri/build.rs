const COMMANDS: &[&str] = &[
    "bootstrap",
    "list_accounts",
    "begin_account_connection",
    "account_connection_status",
    "complete_account_connection",
    "list_folders",
    "start_sync",
    "list_messages",
    "get_message",
    "search_messages",
    "create_draft",
    "update_draft",
    "list_drafts",
    "delete_draft",
    "create_reply_draft",
    "create_send_preview",
    "execute_send",
    "list_plans",
    "approve_plan",
    "execute_plan",
    "undo_action",
    "list_audit",
    "disconnect_account",
    "legacy_migration_status",
    "migrate_legacy",
];

fn main() {
    let manifest = tauri_build::AppManifest::new().commands(COMMANDS);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("failed to build Tauri command permissions");
}
