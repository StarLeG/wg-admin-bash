# AGENTS.md

## What this repo is

WireGuard Hub-and-Spoke admin CLI (one hub, many spokes), two ports:

| File | Target | Version constant |
|---|---|---|
| `wg-admin.sh` | Debian/Ubuntu, root | `VERSION="..."` |
| `wg-admin.ps1` | Windows 10/11/Server, Administrator | `$script:AppVersion` |

SemVer, single version source per script. Spec in gitignored `ТЗ.md` (local only).

## Source of truth

`ТЗ.md` (Russian) is the complete spec: menu tree, add-client dialog, expiry
semantics, target file structure, style rules, acceptance checklist. Read it before
coding. Implement every function fully — no stubs, no `# ... остальной код ...`
placeholders. Each port is one self-contained script file.

`ТЗ.md` is gitignored (private spec) — present in the local workspace only. A
fresh clone won't have it; ask the user to supply it rather than guessing.

## Verify

The workspace is Windows (`D:\VPN`), but the script targets Linux root. Real checks
run in WSL (Ubuntu-24.04 is installed):

```bash
wsl -d Ubuntu-24.04 -- bash -n /mnt/d/VPN/wg-admin.sh
wsl -d Ubuntu-24.04 -- shellcheck /mnt/d/VPN/wg-admin.sh
```

- `shellcheck` is not preinstalled in the WSL distro — install once with
  `sudo apt install shellcheck` inside WSL.
- Runtime acceptance (init server, add clients, expiry) needs a root Debian/Ubuntu
  box and cannot be exercised from this workspace. `bash -n` + clean `shellcheck`
  is the achievable local gate.
- PowerShell tests: `powershell -NoProfile -ExecutionPolicy Bypass -File test-wg-admin.ps1`
- Test suite (root in WSL, isolates paths under `mktemp -d`):
  `wsl -d Ubuntu-24.04 -u root -- bash /mnt/d/VPN/test-wg-admin.sh`
- Live menu smoke (writes real `/etc/wireguard` in WSL):
  `wsl -d Ubuntu-24.04 -u root -- bash /mnt/d/VPN/live-smoke.sh`
- Piping menu input: `read -p` shows prompts only on a tty; `pause` after every
  menu action consumes one line — account for it when scripting input. Also,
  `printf '\n'` via `wsl bash -c '...'` from PowerShell eats backslashes — put
  scripted input in a file instead.

## PowerShell port (`wg-admin.ps1`) gotchas

- **UTF-8 BOM is mandatory** for `.ps1` with Russian text. The Edit tool writes
  UTF-8 without BOM; PowerShell 5.1 then reads it as ANSI (mojibake + parse
  errors). After editing, re-add BOM:
  `[IO.File]::WriteAllText($p, [IO.File]::ReadAllText($p, [Text.Encoding]::UTF8), (New-Object Text.UTF8Encoding $true))`
- PS 5.1 only: no `&&`/`||` pipeline chains, no ternary. Keep 5.1-compatible.
- Never nest double quotes inside `"$(...)"` — use `$(t 'ru' 'en')` or concat.
- `$name: text` inside double quotes is parsed as drive scope — write `${name}:`.
- `[switch]$Version` param collides with `$script:Version` — version lives in
  `$script:AppVersion`.
- Configs in `C:\ProgramData\wg-admin\`; tunnel via `wireguard.exe /installtunnelservice`.
- Dot-source guard (`$MyInvocation.InvocationName -ne '.'`) lets tests load functions.

## Constraints agents get wrong (bash)

- Never `set -e` in this script (kills interactive menus); `set -o pipefail` only.
- Re-apply config with `wg syncconf "${WG_IF}" <(wg-quick strip "${WG_IF}")` —
  restarting `wg-quick@wg0` drops active sessions.
- Expired/disabled peers are disabled, not deleted: comment out their `[Peer]`
  lines and mark `# DISABLED 1`. Extending expiry uncomments them again.
- Private keys via `umask 077`; client configs/keys `chmod 600`; refuse non-root
  via `EUID` check at startup.
- Validate all input before use: names `^[a-zA-Z0-9_-]+$`, IP, CIDR, port. Escape
  variables in sed/awk. No `eval`.
- Expiry input forms `30d` / `12h` / `never` / `YYYY-MM-DD` → `# EXPIRES <unix_ts>`
  in the peer block plus a record in `/etc/wireguard/expiry.db`.
- Every mutating action logs to `/var/log/wg-admin.log` as
  `[YYYY-MM-DD HH:MM:SS] [LEVEL] message` (INFO/WARN/ERROR/DEBUG).
- Style from the spec, not generic house style: `#!/usr/bin/env bash`, constants
  UPPER_CASE at top, snake_case verb functions (`add_client`), **comments in
  Russian**, 2-space indent, lines ≤ 100 chars.
- Version is the `VERSION="..."` constant in the script (SemVer
  `MAJOR.MINOR.PATCH`, spec starts at 1.0.0) — single source; don't duplicate it.

## Git

- Remote `origin`: `git@github.com:StarLeG/wg-admin-bash.git`, branch `main`
  tracks `origin/main`. SSH is authenticated as user `StarLeG`.
- **SSH to github.com:22 is blocked on this network.** `~/.ssh/config` has a
  `Host github.com` entry that routes through `ssh.github.com:443` — keep it.
  HTTPS (Git Credential Manager) also works as a fallback.
- Branch from `main`, never commit feature work directly to it. Branch names:
  `<type>/<kebab-case>`, e.g. `feat/add-client-menu`, `fix/expiry-restore`.
- Commits follow Conventional Commits: type/scope in English, description and
  body in Russian, imperative mood, no trailing period.
  Example: `feat(clients): добавь меню управления клиентами`
- Stage specific paths (`git add <file>`), never `git add -A`. Atomic commits.

## Done means

Spec section `# КРИТЕРИИ ГОТОВНОСТИ`: passes `bash -n` and `shellcheck`, every menu
item works, config apply never drops sessions, keys are mode 600, logs are written.
