use std::collections::{BTreeMap, BTreeSet};

use crate::{
    domain::mail::{Folder, FolderRole, MessageSummary},
    storage::{FolderRecord, MessageBody, MessageRecord},
};

/// Builds stable local folder identifiers while retaining provider identifiers exclusively as
/// remote IDs. Existing IDs are reused so a refresh never invalidates the selected folder.
pub fn folder_records(
    account_id: &str,
    provider_folders: Vec<Folder>,
    existing: &[FolderRecord],
    now: i64,
) -> Vec<FolderRecord> {
    let existing_by_remote = existing
        .iter()
        .map(|folder| (folder.remote_id.as_str(), folder.id.as_str()))
        .collect::<BTreeMap<_, _>>();
    provider_folders
        .into_iter()
        .map(|folder| {
            let remote_id = folder.id.into_inner();
            let id = existing_by_remote
                .get(remote_id.as_str())
                .map(|id| (*id).to_owned())
                .unwrap_or_else(|| local_folder_id(account_id, &remote_id));
            FolderRecord {
                id,
                account_id: account_id.to_owned(),
                remote_id,
                parent_id: None,
                name: folder.name,
                role: Some(folder_role_name(folder.role).to_owned()),
                unread_count: folder.unread_count.unwrap_or(0).min(u32::MAX as u64) as u32,
                total_count: folder.total_count.unwrap_or(0).min(u32::MAX as u64) as u32,
                updated_at: now,
            }
        })
        .collect()
}

/// Converts a provider summary into persistent metadata and every known local folder association.
pub fn message_record(
    account_id: &str,
    message: MessageSummary,
    folders: &[FolderRecord],
    now: i64,
) -> (MessageRecord, Vec<String>) {
    let known = folders
        .iter()
        .map(|folder| (folder.remote_id.as_str(), folder))
        .collect::<BTreeMap<_, _>>();
    let mut associations = BTreeSet::new();
    let mut primary: Option<(&FolderRecord, u8)> = None;
    let mut starred = false;
    let mut sent = false;
    let mut draft = false;
    for remote in &message.folder_ids {
        starred |= remote.as_str().eq_ignore_ascii_case("starred");
        let Some(folder) = known.get(remote.as_str()).copied() else {
            continue;
        };
        associations.insert(folder.id.clone());
        let rank = folder_rank(folder.role.as_deref());
        if primary.map_or(true, |(_, current)| rank < current) {
            primary = Some((folder, rank));
        }
        sent |= matches!(folder.role.as_deref(), Some("sent"));
        draft |= matches!(folder.role.as_deref(), Some("drafts"));
    }
    let mut flags = Vec::with_capacity(5);
    if message.unread {
        flags.push("unread");
    }
    if message.has_attachments {
        flags.push("attachment");
    }
    if starred {
        flags.push("starred");
    }
    if sent {
        flags.push("sent");
    }
    if draft {
        flags.push("draft");
    }
    let sender = message
        .from
        .as_ref()
        .map(|address| address.address.clone())
        .unwrap_or_else(|| "unknown".to_owned());
    let recipients = message
        .to
        .iter()
        .map(|address| address.address.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let remote_id = message.id.into_inner();
    (
        MessageRecord {
            id: local_message_id(account_id, &remote_id),
            account_id: account_id.to_owned(),
            folder_id: primary.map(|(folder, _)| folder.id.clone()),
            remote_id,
            thread_id: message.thread_id,
            subject: message.subject,
            sender,
            recipients,
            snippet: message.preview,
            flags: flags.join(","),
            sent_at: sent.then_some(message.received_at_ms),
            received_at: message.received_at_ms,
            size_bytes: 0,
            body: MessageBody {
                text: None,
                html: None,
            },
            updated_at: now,
        },
        associations.into_iter().collect(),
    )
}

fn local_folder_id(account_id: &str, remote_id: &str) -> String {
    let seed = format!("{account_id}\0{remote_id}");
    format!("folder:{}", crate::agent::sha256_hex(seed.as_bytes()))
}

pub(crate) fn local_message_id(account_id: &str, remote_id: &str) -> String {
    let seed = format!("{account_id}\0{remote_id}");
    format!("message:{}", crate::agent::sha256_hex(seed.as_bytes()))
}

fn folder_role_name(role: FolderRole) -> &'static str {
    match role {
        FolderRole::Inbox => "inbox",
        FolderRole::Sent => "sent",
        FolderRole::Drafts => "drafts",
        FolderRole::Archive => "archive",
        FolderRole::Trash => "trash",
        FolderRole::Spam => "spam",
        FolderRole::Other => "other",
    }
}

fn folder_rank(role: Option<&str>) -> u8 {
    match role {
        Some("inbox") => 0,
        Some("drafts") => 1,
        Some("sent") => 2,
        Some("trash") => 3,
        Some("spam") => 4,
        Some("archive") => 5,
        _ => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::mail::{EmailAddress, FolderId, MessageId};

    fn folder(id: &str, role: FolderRole) -> Folder {
        Folder {
            id: FolderId::new(id).unwrap(),
            name: id.to_owned(),
            role,
            unread_count: Some(1),
            total_count: Some(2),
        }
    }

    #[test]
    fn refresh_reuses_folder_ids_and_message_keeps_all_memberships() {
        let first = folder_records(
            "account-a",
            vec![
                folder("INBOX", FolderRole::Inbox),
                folder("SENT", FolderRole::Sent),
            ],
            &[],
            1,
        );
        let refreshed = folder_records(
            "account-a",
            vec![
                folder("INBOX", FolderRole::Inbox),
                folder("SENT", FolderRole::Sent),
            ],
            &first,
            2,
        );
        assert_eq!(first[0].id, refreshed[0].id);
        assert_eq!(first[1].id, refreshed[1].id);

        let (message, memberships) = message_record(
            "account-a",
            MessageSummary {
                id: MessageId::new("remote-message").unwrap(),
                folder_ids: vec![
                    FolderId::new("INBOX").unwrap(),
                    FolderId::new("SENT").unwrap(),
                    FolderId::new("STARRED").unwrap(),
                ],
                thread_id: Some("thread".into()),
                subject: "Subject".into(),
                from: Some(EmailAddress {
                    address: "sender@example.com".into(),
                    display_name: None,
                }),
                to: Vec::new(),
                received_at_ms: 42,
                unread: true,
                has_attachments: false,
                preview: "Preview".into(),
            },
            &refreshed,
            3,
        );
        assert_eq!(memberships.len(), 2);
        assert!(memberships.contains(&refreshed[0].id));
        assert!(memberships.contains(&refreshed[1].id));
        assert_eq!(message.folder_id.as_deref(), Some(refreshed[0].id.as_str()));
        assert_eq!(message.flags, "unread,starred,sent");
        assert_eq!(message.sent_at, Some(42));
    }

    #[test]
    fn local_ids_are_account_scoped() {
        assert_ne!(
            local_message_id("account-a", "same-remote"),
            local_message_id("account-b", "same-remote")
        );
        assert_ne!(
            local_folder_id("account-a", "INBOX"),
            local_folder_id("account-b", "INBOX")
        );
    }
}
