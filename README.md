# Campus osquery extensions

osquery extensions for Mac inventory and management at Campus.

## Extensions

### `mac_enclosure_color`

Exposes a `mac_enclosure_color` table returning the running Mac's enclosure color (e.g. "Space Black", "Midnight", "Sky Blue").

```sql
SELECT * FROM mac_enclosure_color;
-- color        | color_code | model        | product_type
-- Space Black  | 9          | MacBook Pro  | Mac16,5
```

Data sources:

- `MobileGestalt` (`/usr/lib/libMobileGestalt.dylib`) — `ProductType`, `DeviceEnclosureColor`.
- `system_profiler SPHardwareDataType -json` — Model Name (MobileGestalt's marketing-name keys return "macOS" on recent macOS, so we shell out for this).

The numeric `DeviceEnclosureColor` is mapped to a color name using the convention popularized by [munkireport's iBridge module](https://github.com/munkireport/ibridge) — the same numeric code maps to different colors on different Mac product lines, so model name disambiguation is required.

### `touchid`

Exposes two macOS Touch ID tables. **Apple Silicon only.**

```sql
SELECT * FROM touchid_system_config;
-- touchid_compatible | secure_enclave | touchid_enabled | touchid_unlock
-- 1                  | Mac16,5        | 1               | 1

SELECT * FROM touchid_user_config;            -- one row per local account
SELECT * FROM touchid_user_config WHERE uid = 501;
-- uid | fingerprints_registered | touchid_unlock | touchid_applepay | effective_unlock | effective_applepay
-- 501 | 1                       | 1              | 1                | 1                | 1
```

**uid selection.** With no `WHERE uid =`, the table returns a row for every real local account (uid 501–60000, enumerated via `dscl . -list /Users UniqueID`). Pass `WHERE uid =` to target a specific account.

The two pieces of per-user data have **different access models**, which is why some columns can be empty:

| Column(s) | Source | Needs root? | Needs the user logged in? |
| --- | --- | --- | --- |
| `fingerprints_registered` | `bioutil -c -s` (reads all users at once) | **Yes** | No |
| `touchid_unlock`, `touchid_applepay`, `effective_*` | `bioutil -r` via `launchctl asuser <uid>` | No | **Yes** |

`fleetd` / `orbit` runs extensions as **root**, so `bioutil -c -s` works there. When a column can't be read it is left **empty (unknown)** rather than `0`, so an enabled-but-logged-out user is never misreported as disabled:

- Not running as root → `fingerprints_registered` is empty.
- User not logged in → the four config flags are empty (the count is still reported).

Data sources:

- `bioutil -r -s` — system-wide Touch ID configuration (compatibility, enabled, unlock).
- `bioutil -r` (per-uid, via `launchctl asuser`) — user unlock / Apple Pay flags, including "effective" flags.
- `bioutil -c -s` (root) — enrolled fingerprint template count for all users.
- `system_profiler SPiBridgeDataType` — SoC model identifier reported as `secure_enclave` (every Apple Silicon Mac has an on-die Secure Enclave).

`bioutil` output is parsed by line **label** rather than field position, so the tables stay correct on newer macOS releases that add configuration lines. When a user's count is known to be zero, the `effective_*` flags are forced to `0` to work around a `bioutil` quirk that can otherwise report them as enabled.

### Build

```sh
cd touchid   # or: cd mac_enclosure_color
GOOS=darwin go build -o "$(basename "$PWD").ext"
```

Or build everything with `make build` from the repo root.

### Test

```sh
osqueryi --extension ./mac_enclosure_color.ext
osquery> SELECT * FROM mac_enclosure_color;

osqueryi --extension ./touchid/touchid.ext
osquery> SELECT * FROM touchid_system_config;
osquery> SELECT * FROM touchid_user_config WHERE uid = 501;
```

Run the unit tests for all extensions with `make test`.

### Deploy with Fleet

Drop the `.ext` binary into your Fleet `fleetd` agent's extensions directory; orbit auto-loads extensions on startup. Sign and notarize the binary with your Developer ID for clean Gatekeeper handling.

## License

MIT
