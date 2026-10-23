# macOS NetworkExtension

On macOS the kernel tier is a NetworkExtension content filter. `profast firewall
apply` still uses a pf anchor by default because it needs no entitlement; the
extension is what makes the decision per flow inside the sandbox.

## What is here

| File                       | Purpose                                             |
| -------------------------- | --------------------------------------------------- |
| `FilterDataProvider.swift` | `NEFilterDataProvider` that answers allow/drop        |
| `Info.plist`               | extension point `com.apple.networkextension.filter-data` |
| `ProFast.entitlements`     | app group + networkextension entitlement             |

## Policy contract

`profastd` writes into the shared app-group defaults:

```swift
UserDefaults(suiteName: "group.com.profast.net")?.set([
    "denyInbound": true,
    "ports": [40000, 40001],
    "generation": 7,
], forKey: "policy")
```

The provider re-reads the dictionary on every new flow and uses `generation` to
log reloads. Loopback, `fd00::/8` (the mirage prefix) and RFC1918 addresses are
treated as nearby and always allowed, matching `allow_lan`.

## Building

1. Create a macOS app + System Extension target in Xcode 15 or newer.
2. Add this file to the extension target, set the bundle id to
   `net.profast.extension` and paste `Info.plist` and `ProFast.entitlements`.
3. Request the `com.apple.developer.networking.networkextension` entitlement
   with the `content-filter-provider` value for your team id. Without it the
   extension installs but never receives flows.
4. Enable the extension from the host app with
   `NEFilterManager.shared().isEnabled = true`, then approve it in
   System Settings > Privacy & Security > Network.
5. System extensions must be notarised for distribution; locally, `codesign -s -`
   with the entitlement is enough for development.

## Review checklist

- `handleNewFlow` must never block: it runs on a hot path. The skeleton reads a
  small dictionary, which is acceptable; a larger policy belongs in a
  `NEFilterControlProvider` pushed at start.
- Confirm that `drop()` from a data provider does not leak the reason to the
  remote peer (it does not).
- The filter applies to outbound flows too when `filterSockets` includes them;
  the skeleton only inspects inbound destinations and must be extended before
  claiming outbound enforcement.
