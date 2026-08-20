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

### `touchid` — moved upstream

The `touchid_system_config` and `touchid_user_config` tables now live in
[macadmins/osquery-extension](https://github.com/macadmins/osquery-extension)
as of [v1.5.1](https://github.com/macadmins/osquery-extension/releases/tag/v1.5.1)
(see [PR #110](https://github.com/macadmins/osquery-extension/pull/110) and
[PR #111](https://github.com/macadmins/osquery-extension/pull/111)). Use the
upstream extension instead of this repo for Touch ID data.

### Build

```sh
cd mac_enclosure_color
GOOS=darwin go build -o "$(basename "$PWD").ext"
```

Or build everything with `make build` from the repo root.

### Test

```sh
osqueryi --extension ./mac_enclosure_color.ext
osquery> SELECT * FROM mac_enclosure_color;
```

Run the unit tests for all extensions with `make test`.

### Deploy with Fleet

Drop the `.ext` binary into your Fleet `fleetd` agent's extensions directory; orbit auto-loads extensions on startup. Sign and notarize the binary with your Developer ID for clean Gatekeeper handling.

## License

MIT
