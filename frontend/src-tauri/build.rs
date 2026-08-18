const COMMANDS: &[&str] = &[
    "bootstrap",
    "list_accounts",
    "list_folders",
    "start_sync",
    "list_messages",
    "get_message",
    "search_messages",
    "create_draft",
    "list_plans",
    "approve_plan",
    "execute_plan",
    "undo_action",
    "list_audit",
    "disconnect_account",
];

fn main() {
    let manifest = tauri_build::AppManifest::new().commands(COMMANDS);
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(manifest))
        .expect("failed to build Tauri command permissions");
}
