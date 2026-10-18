// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import SwiftUI

/// Keeps the existing tunnel manager as the single source of truth, including changes from Settings.
final class TVTunnelStore: ObservableObject, TunnelsManagerListDelegate, TunnelsManagerActivationDelegate {
    @Published var tunnels: [TunnelContainer] = []
    @Published var isLoading = true
    @Published var error: String?
    @Published var isSaving = false
    private var manager: TunnelsManager?
    private var observations: [NSKeyValueObservation] = []

    init() {
        Logger.configureGlobal(tagged: "APP", withFilePath: FileManager.logFileURL?.path)
        load()
    }

    func load() {
        isLoading = true
        TunnelsManager.create { [weak self] result in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.isLoading = false
                switch result {
                case .success(let manager):
                    self.manager = manager
                    manager.tunnelsListDelegate = self
                    manager.activationDelegate = self
                    self.refresh()
                case .failure(let error): self.show(error)
                }
            }
        }
    }

    func refresh() {
        tunnels = manager?.mapTunnels { $0 } ?? []
        observations = tunnels.flatMap { tunnel in
            [tunnel.observe(\.status) { [weak self] _, _ in
                DispatchQueue.main.async { self?.objectWillChange.send() }
            }, tunnel.observe(\.isActivateOnDemandEnabled) { [weak self] _, _ in
                DispatchQueue.main.async { self?.objectWillChange.send() }
            }]
        }
    }

    func resume() {
        manager?.reload()
        manager?.refreshStatuses()
    }

    func save(name: String, text: String, replacing tunnel: TunnelContainer? = nil, completion: @escaping (String?) -> Void) {
        guard let manager = manager, !isSaving else {
            completion("Tunnel manager is not ready. Try again.")
            return
        }
        let name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, name.count <= 128 else {
            completion("Enter a tunnel name of 1–128 characters.")
            return
        }
        let configuration: TunnelConfiguration
        do {
            configuration = try TunnelConfiguration(fromWgQuickConfig: text, called: name)
        } catch {
            // Parser errors can contain private configuration values. Do not display or log them.
            completion("Invalid WireGuard configuration. Check the keys, addresses, and peer settings.")
            return
        }
        isSaving = true
        let finished: (TunnelsManagerError?) -> Void = { [weak self] error in
            DispatchQueue.main.async {
                self?.isSaving = false
                self?.refresh()
                completion(error.map { $0.alertText.message })
            }
        }
        if let tunnel = tunnel {
            manager.modify(tunnel: tunnel, tunnelConfiguration: configuration, onDemandOption: tunnel.onDemandOption, completionHandler: finished)
        } else {
            manager.add(tunnelConfiguration: configuration) { result in
                switch result {
                case .success: finished(nil)
                case .failure(let error): finished(error)
                }
            }
        }
    }

    func toggle(_ tunnel: TunnelContainer) {
        guard let manager = manager else { return }
        if tunnel.status == .inactive {
            manager.startActivation(of: tunnel)
        } else if tunnel.isActivateOnDemandEnabled {
            manager.setOnDemandEnabled(false, on: tunnel) { [weak self] error in
                if let error = error { self?.show(error) } else { manager.startDeactivation(of: tunnel) }
            }
        } else {
            manager.startDeactivation(of: tunnel)
        }
    }

    func setOnDemand(_ enabled: Bool, tunnel: TunnelContainer) {
        guard let manager = manager, let config = tunnel.tunnelConfiguration else { return }
        manager.modify(tunnel: tunnel, tunnelConfiguration: config, onDemandOption: enabled ? .anyInterface(.anySSID) : .off) { [weak self] error in
            if let error = error { self?.show(error); return }
            manager.setOnDemandEnabled(enabled, on: tunnel) { [weak self] error in
                if let error = error { self?.show(error) }
                self?.refresh()
            }
        }
    }

    func remove(_ tunnel: TunnelContainer) {
        manager?.remove(tunnel: tunnel) { [weak self] error in
            if let error = error { self?.show(error) }
        }
    }

    func show(_ error: WireGuardAppError) {
        DispatchQueue.main.async { self.error = error.alertText.title + "\n" + error.alertText.message }
    }

    func tunnelAdded(at index: Int) { refresh() }
    func tunnelModified(at index: Int) { refresh() }
    func tunnelMoved(from oldIndex: Int, to newIndex: Int) { refresh() }
    func tunnelRemoved(at index: Int, tunnel: TunnelContainer) { refresh() }
    func tunnelActivationAttemptFailed(tunnel: TunnelContainer, error: TunnelsManagerActivationAttemptError) { show(error) }
    func tunnelActivationFailed(tunnel: TunnelContainer, error: TunnelsManagerActivationError) { show(error) }
    func tunnelActivationAttemptSucceeded(tunnel: TunnelContainer) { refresh() }
    func tunnelActivationSucceeded(tunnel: TunnelContainer) { refresh() }
}
