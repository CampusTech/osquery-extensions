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

### Build

```sh
cd mac_enclosure_color
GOOS=darwin go build -o mac_enclosure_color.ext
```

### Test

```sh
osqueryi --extension ./mac_enclosure_color.ext
osquery> SELECT * FROM mac_enclosure_color;
```

### Deploy with Fleet

Drop the `.ext` binary into your Fleet `fleetd` agent's extensions directory; orbit auto-loads extensions on startup. Sign and notarize the binary with your Developer ID for clean Gatekeeper handling.

## License

MIT
