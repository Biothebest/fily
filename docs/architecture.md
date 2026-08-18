# Fily desktop architecture

## Current state

Fily has three existing layers:

- `frontend/`: React and TypeScript presentation. It currently calls a local HTTP API and renders job-application records, evidence, account state, and assistant answers.
- `fily/`: the original Python local-first engine. It owns SQLite persistence, Gmail read-only synchronization, extraction, search, approval-gated file actions, and audit records.
- `frontend/src-tauri/`: the Tauri 2 shell. The first desktop build packaged the Python engine as a sidecar and started its loopback HTTP server.

The sidecar established packaging and verified macOS/Windows installers, but it is not the final trust boundary. A loopback HTTP API and Python-owned provider/storage operations do not satisfy the desktop security model. The desktop application will therefore move trusted operations into Rust and remove the packaged sidecar. The Python CLI remains useful as an independent migration and diagnostic tool; the desktop runtime will not invoke it.

## Reused responsibilities

| Existing responsibility | Existing code | Desktop direction |
| --- | --- | --- |
| Job-application presentation | `frontend/components/fily/*` | Reuse and adapt to typed Tauri commands. |
| Domain naming and evidence model | `fily/models.py`, `fily/jobs.py` | Preserve observable fields in Rust domain types. |
| Approval-first semantics | `fily/agent.py`, `fily/store.py` | Preserve the proposal/approval/execution split in Rust. |
| Gmail incremental pagination | `fily/gmail.py`, `fily/gmail_sync.py` | Reimplement behind the Rust `MailProvider` interface. |
| Local search behavior | SQLite FTS in `fily/store.py` | Reimplement in the encrypted Rust database. |
| Desktop interface | `frontend/` | Keep React presentation and local UI state only. |
| Desktop packaging | `frontend/src-tauri/`, desktop CI | Keep Tauri 2 and platform build jobs. |

No second desktop framework is used.

## Target trust boundary

```text
React + TypeScript
  presentation and ephemeral interface state only
        |
        | generated/typed invoke commands
        v
Tauri 2 command boundary
  narrow commands, serde validation, per-window capabilities
        |
        v
Rust trusted core
  providers | sync | encrypted SQLite | FTS | attachments
  credential vault | agent policy | approvals | audit | undo
        |
        +--> macOS Keychain / Windows Credential Manager
        +--> Gmail HTTPS / IMAP / SMTP
```

React never receives refresh tokens, passwords, database keys, unrestricted paths, or provider client internals. Commands accept bounded identifiers, search text, public OAuth authorization results, and explicit approval decisions. Provider secrets are written directly to the OS credential vault and represented in application state only by opaque credential references.

## Provider boundary

All mail providers implement one internal Rust `MailProvider` interface:

- connect or complete authorization
- list mailboxes/folders
- incrementally synchronize using a provider cursor
- retrieve normalized messages
- search
- create drafts
- send
- move
- archive
- trash
- disconnect

`GmailProvider`, `ImapSmtpProvider`, `YahooProvider`, and `ICloudProvider` contain provider-specific endpoints, folder semantics, cursor rules, and authentication behavior. UI code cannot branch on provider protocol details.

## Data and credentials

The local database stores normalized accounts, folders, messages, attachment metadata, synchronization cursors, agent plans, approvals, audit events, and recovery records. Sensitive message fields are encrypted before persistence with an application key stored only in the OS credential vault. Search uses a privacy-preserving local index over normalized text; database files never contain provider passwords, OAuth refresh tokens, or encryption keys.

Credential records use stable opaque account IDs. macOS stores secrets in Keychain. Windows stores secrets in Credential Manager. Disconnect removes the provider secret and invalidates the local account session.

## Untrusted content

Message HTML is sanitized in Rust before it crosses the command boundary. Scripts, forms, event handlers, embedded frames, remote images, and active content are removed or blocked. Attachments are addressed by opaque IDs, written only inside the managed attachment directory, checked for size and filename traversal, and opened only after an explicit user action. Email content is data; it cannot select or invoke a privileged command.

## Agent authorization

Permissions are explicit and ordered by capability, not inferred from a prompt: `read`, `organize`, `draft`, `send`, `move`, and `delete`. Plans capture affected account/message IDs, reason, requested capability, preview, expiration, and an integrity hash. `send`, `delete`, bulk changes, and rule creation require a visible confirmation by default. Execution verifies the approved plan hash and current message versions. Audit records omit message bodies and secrets. Reversible operations retain recovery metadata and expose undo until provider or retention limits make reversal impossible.
