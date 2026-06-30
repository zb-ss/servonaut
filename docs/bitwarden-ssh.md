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

Like everything else here, the manager reads your vault locally; the server
join uses only the opaque pointers Servonaut already stores.

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
