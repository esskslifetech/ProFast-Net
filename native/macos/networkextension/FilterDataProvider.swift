// ProFast-Net NetworkExtension data provider (skeleton).
//
// The system extension is the macOS equivalent of the WFP callout and the XDP
// program: it makes the accept/drop decision for new flows inside the
// NetworkExtension sandbox, so a probe is rejected before it reaches the app.
//
// Policy is written by `profastd` into the shared app-group defaults:
//   suite  group.com.profast.net
//   key    policy          [String: Any]
//     denyInbound          Bool    default-deny when true
//     ports                [Int]   ports the rotating locator accepts
//     generation           Int     bumped on every change, used for reload
//
// Build: see README.md. The provider needs the
// com.apple.developer.networking.networkextension entitlement with the
// `content-filter-provider` value, which Apple grants per team id.

import NetworkExtension
import os.log

private let sharedSuite = "group.com.profast.net"
private let log = OSLog(subsystem: "net.profast.extension", category: "filter")

struct Policy {
    var denyInbound: Bool
    var ports: Set<Int>
    var generation: Int

    static let allowAll = Policy(denyInbound: false, ports: [], generation: 0)

    static func load() -> Policy {
        guard let defaults = UserDefaults(suiteName: sharedSuite),
              let raw = defaults.dictionary(forKey: "policy") else {
            return .allowAll
        }
        let ports = (raw["ports"] as? [Int]) ?? []
        return Policy(
            denyInbound: (raw["denyInbound"] as? Bool) ?? false,
            ports: Set(ports),
            generation: (raw["generation"] as? Int) ?? 0
        )
    }
}

final class FilterDataProvider: NEFilterDataProvider {
    private var policy = Policy.load()

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        os_log("starting ProFast filter, deny=%{public}@", log: log,
               String(describing: policy.denyInbound))
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        os_log("stopping ProFast filter: %{public}d", log: log, reason.rawValue)
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        // Re-read the policy when the daemon changed it. The dictionary is tiny
        // and this keeps the extension stateless across restarts.
        let latest = Policy.load()
        if latest.generation != policy.generation {
            policy = latest
            os_log("policy reloaded, generation %{public}d", log: log, policy.generation)
        }

        guard policy.denyInbound else {
            return .allow()
        }

        guard let socketFlow = flow as? NEFilterSocketFlow,
              let remote = socketFlow.remoteEndpoint as? NWHostEndpoint,
              let port = Int(remote.port) else {
            // Nothing to match on: let the kernel's own firewall decide.
            return .allow()
        }

        // Loopback and link-local peers are "nearby" by definition and are
        // always allowed, mirroring `allow_lan` in the user-mode policy.
        if isLocal(remote.hostname) {
            return .allow()
        }

        if policy.ports.contains(port) {
            return .allow()
        }

        return .drop()
    }

    private func isLocal(_ host: String) -> Bool {
        if host.hasPrefix("127.") || host == "::1" {
            return true
        }
        if host.hasPrefix("fe80:") || host.hasPrefix("fd") {
            return true
        }
        if host.hasPrefix("10.") || host.hasPrefix("192.168.") {
            return true
        }
        // 172.16.0.0/12
        let parts = host.split(separator: ".")
        if parts.count == 4, parts[0] == "172", let second = Int(parts[1]) {
            return (16...31).contains(second)
        }
        return false
    }
}
