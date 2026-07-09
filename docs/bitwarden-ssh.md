# Bitwarden SSH key picker

Servonaut can resolve a server's SSH private key straight from your **Bitwarden
Password Manager** vault, so you never store the key on disk. Instead of pasting
a vault item UUID by hand, you **unlock your vault and pick the key from a list**.

> **This is a local feature.** The picker runs the `bw` CLI on *your* machine.
> Your master password and your vault contents never leave your computer —
> Servonaut's servers only ever store an opaque pointer (`item_id`) to the vault
> item, never the key itself.

Available on the **Solo** and **Teams** plans. Free-tier sessions see an upgrade
card instead of the picker.

## One-time setup

1. **Install the Bitwarden CLI** (`bw`) and put it on your `PATH`:
   <https://bitwarden.com/help/cli/>
2. **Log in once, in your own terminal** (this is the only step Servonaut does
   *not* drive — it involves your email, master password, and 2FA):

   ```bash
   bw login
   ```

   Servonaut detects whether you are logged in; it never handles `bw login`
   itself.
3. **Store your server keys as native SSH-key items** in Bitwarden
   (BW 2023.10+). Servonaut reads the standard `sshKey` field — it does not look
   in notes or attachments.

## Picking a key for a server

1. Open a server's actions screen and choose **Manage/Verify SSH Ref**.
2. Click **Pick from vault…**.
3. If your vault is locked, Servonaut prompts for your **master password** and
   unlocks it **for the current session only** (the session key is held in
   memory and discarded when you quit — you re-unlock on the next launch).
4. Browse the list of SSH-key items, optionally typing in the search box, and
   select the one for this server.
5. The reference is saved. The editor shows the item **name** (not the raw
   UUID).

### The "Servonaut" folder

By default the picker lists only items in a Bitwarden folder named **Servonaut**,
which it creates automatically the first time you use the picker. This keeps the
list focused on server keys. Two ways to widen or change the scope:

- Toggle **"… folder only"** off in the picker to browse your whole vault.
- Change the folder name under **Settings → Bitwarden SSH Vault → Vault folder**.
  This is a local preference and does not affect the server-side vault wiring.

### Advanced — paste a UUID

The editor keeps an **Advanced** section where you can paste an item UUID,
collection ID, and vault URL directly — useful for items outside the Servonaut
folder or power-user workflows. The collection ID and vault URL default to the
values from your saved vault wiring, so you rarely need to re-enter them.

## How resolution works on connect

When you SSH to a server that has a Bitwarden ref, Servonaut:

1. Reads the stored `item_id` for that instance from the server-side pointer.
2. Runs `bw get item <item_id>` locally, using the in-memory session from your
   unlock (falling back to an ambient `BW_SESSION` if you exported one by hand).
3. Writes the resolved key to a temporary `0600` file for the SSH session.

The private key body is only ever read at connect time and is never rendered in
the UI, written to a log, or sent anywhere.

### MCP / headless resolution

The SSH-backed MCP tools (`run_command`, `get_logs`, `get_server_info`,
`transfer_file`, and the incident-response probes) use the same chain: when an
instance has a stored **personal** Bitwarden ref, the key is resolved from the
vault and preferred over local `~/.ssh` discovery. Requirements and behavior:

- **Ambient `BW_SESSION` required.** The headless process has no unlock
  prompt — run `bw unlock` and export `BW_SESSION` in the environment the MCP
  server (or `servonaut connect`) runs in. If the vault is locked or the `bw`
  CLI is missing, the tool silently falls back to the local key, so a working
  local setup never breaks.
- **Personal refs only.** Team-shared refs are not resolved on the headless
  surface yet.
- **Per-call temp key lifecycle.** The resolved key is written to a `0600`
  file under `~/.servonaut/tmp/` immediately before the ssh/scp subprocess and
  deleted (zero-overwritten, then unlinked) as soon as it exits — the key
  never persists between tool calls.
- **Limitation:** on servers that don't expose ref reads over the API, refs
  are read from a device-local mirror written when the ref was saved. A ref
  saved on another device resolves here only if the server exposes it.

## Vault manager (fleet view)

The sidebar entry **🗝 BW SSH Vault** opens a manager screen — the same
"manager panel" shape the cloud providers have. It lists the SSH-key items in
your Servonaut folder, joined with **which servers reference each key** and that
server's last verify status (green = verified, red = failed, — = none).

From the manager you can:

- **Refresh** (`F5`) — re-read the vault and re-compute the join.
- **Open in BW** (`o`) — open the selected key in the Bitwarden web vault.
- **Manage ref** (`e`) — open the SSH-ref editor for a server that references
  the selected key, so you can re-pick or clear it.
- **Import keys** (`a`) — scan a local directory (default `~/.ssh`) and upload
  keys into the vault. See below.

Like everything else here, the manager reads your vault locally; the server
join uses only the opaque pointers Servonaut already stores.

## Importing keys from ~/.ssh

**Import keys** (`a`) in the vault manager moves your existing local keys into
the vault as native Bitwarden SSH items:

1. **Pick a directory.** A picker opens rooted at your home directory, with
   `~/.ssh` prefilled. Any directory works — hidden directories are shown.
2. **Review the scan.** Servonaut scans the directory (non-recursive) for
   private-key files and lists each one with its type and fingerprint.
   Unencrypted keys are pre-selected; passphrase-protected keys show a
   🔒 marker and are opt-in — tick each one you want to import.
3. **Passphrase prompts.** For each selected encrypted key you are asked for
   its passphrase once, so the key can be decrypted for upload. A wrong
   passphrase just re-prompts; **Skip** leaves that key out. The passphrase is
   used in-memory only — it is never logged, written to disk, or passed to any
   command line.
4. **Import.** Selected keys are created as SSH items in your **Servonaut**
   vault folder (or the folder name configured in Settings) and a vault sync
   runs so they appear on your other devices.

What to expect:

- **Vault encryption replaces the file passphrase.** The imported copy is
  protected by your Bitwarden vault's encryption; the original file passphrase
  is not kept on the vault copy. Anyone who can unlock your vault can use the
  key — exactly like every other item in it.
- **Your original files are untouched.** The import reads your key files; it
  never modifies or deletes them.
- **Keys are uploaded to your Bitwarden vault.** The key material goes to
  wherever your vault lives (bitwarden.com or your self-hosted server), end-to-
  end encrypted by Bitwarden. Servonaut's own servers never see it.
- **Duplicates are skipped by fingerprint.** A key whose SHA256 fingerprint
  already exists anywhere in your vault is shown as *already in vault* and is
  not created twice. If the vault listing fails during the scan (expired
  session, timeout), the import is blocked rather than risking duplicates —
  cancel and reopen the dialog to retry.
- Unreadable or unsupported files are listed dimmed and skipped.

## Settings

**Settings → Bitwarden SSH Vault** shows:

- the current vault wiring (vault URL, default collection),
- the local **Vault folder** name,
- a live **Bitwarden CLI** status line (installed / logged in / locked /
  unlocked) with an **Unlock now** action.

## Notes & limitations (v1)

- **Unlock only, not login.** Servonaut handles `bw unlock`; the one-time
  `bw login` stays a manual shell step.
- **SSH-key items only.** Username/password login items are a planned follow-up.
- **Session is in-memory only.** A "remember on this device" option is planned
  but not yet available.
