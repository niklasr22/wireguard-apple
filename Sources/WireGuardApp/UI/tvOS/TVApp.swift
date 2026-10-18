// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import Combine
import CoreImage.CIFilterBuiltins
import SwiftUI

@main
struct WireGuardTVApp: App {
    @StateObject private var store = TVTunnelStore()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            NavigationStack {
                List {
                    Section("Tunnels") {
                        if store.isLoading { ProgressView("Loading tunnels…") }
                        if !store.isLoading && store.tunnels.isEmpty {
                            Text("Add a tunnel to get started.")
                        }
                        ForEach(store.tunnels, id: \.self) { tunnel in
                            NavigationLink {
                                TVTunnelDetail(tunnel: tunnel).environmentObject(store)
                            } label: {
                                HStack {
                                    Text(tunnel.name)
                                    Spacer()
                                    Text(tunnel.status.debugDescription.capitalized)
                                        .foregroundStyle(tunnel.status == .active ? .green : .secondary)
                                }
                            }
                        }
                    }
                    Section {
                        NavigationLink("Add tunnel") {
                            TVImportView().environmentObject(store)
                        }
                        NavigationLink("View log") { TVLogView() }
                        Button("Reload tunnels") { store.load() }
                    }
                }
                .safeAreaInset(edge: .top, spacing: 20) {
                    HStack(spacing: 20) {
                        Image("WireGuardMark")
                            .resizable()
                            .scaledToFit()
                            .frame(width: 54, height: 54)
                            .padding(8)
                            .background(Color(red: 132 / 255, green: 24 / 255, blue: 24 / 255))
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                            .accessibilityHidden(true)
                        Text("WireGuard").font(.largeTitle.weight(.semibold))
                        Spacer()
                    }
                    .padding(.horizontal, 80)
                    .padding(.top, 20)
                }
            }
            .alert("WireGuard", isPresented: Binding(get: { store.error != nil }, set: { if !$0 { store.error = nil } })) {
                Button("OK", role: .cancel) { store.error = nil }
            } message: {
                Text(store.error ?? "")
            }
            .onChange(of: scenePhase) { _, phase in
                if phase == .active { store.resume() }
            }
        }
    }
}

private struct TVTunnelDetail: View {
    @EnvironmentObject var store: TVTunnelStore
    @Environment(\.dismiss) private var dismiss
    let tunnel: TunnelContainer
    @State private var runtime: TunnelConfiguration?
    @State private var confirmDelete = false
    @State private var polling = false
    private let timer = Timer.publish(every: 5, on: .main, in: .common).autoconnect()

    var body: some View {
        List {
            Section("Connection") {
                Text("Status: \(tunnel.status.debugDescription.capitalized)")
                Button(tunnel.status == .inactive ? "Connect" : "Disconnect") { store.toggle(tunnel) }
                    .disabled(![TunnelStatus.inactive, .active, .reasserting].contains(tunnel.status))
                Toggle("Connect on demand", isOn: Binding(get: { tunnel.isActivateOnDemandEnabled }, set: { store.setOnDemand($0, tunnel: tunnel) }))
            }
            if let configuration = runtime ?? tunnel.tunnelConfiguration {
                Section("Interface") {
                    Text("Public key: \(configuration.interface.privateKey.publicKey.base64Key)")
                    Text("Addresses: \(configuration.interface.addresses.map { $0.stringRepresentation }.joined(separator: ", "))")
                    Text("DNS: \(configuration.interface.dns.map { $0.stringRepresentation }.joined(separator: ", "))")
                }
                ForEach(Array(configuration.peers.enumerated()), id: \.offset) { index, peer in
                    Section("Peer \(index + 1)") {
                        Text("Public key: \(peer.publicKey.base64Key)")
                        if let endpoint = peer.endpoint { Text("Endpoint: \(endpoint.stringRepresentation)") }
                        Text("Allowed IPs: \(peer.allowedIPs.map { $0.stringRepresentation }.joined(separator: ", "))")
                        if let received = peer.rxBytes { Text("Received: \(ByteCountFormatter.string(fromByteCount: Int64(clamping: received), countStyle: .binary))") }
                        if let sent = peer.txBytes { Text("Sent: \(ByteCountFormatter.string(fromByteCount: Int64(clamping: sent), countStyle: .binary))") }
                        if let handshake = peer.lastHandshakeTime { Text("Last handshake: \(handshake.formatted())") }
                    }
                }
            }
            Section("Manage") {
                NavigationLink("Replace configuration or rename") {
                    TVImportView(replacing: tunnel).environmentObject(store)
                }
                Button("Delete tunnel") { confirmDelete = true }
            }
        }
        .navigationTitle(tunnel.name)
        .confirmationDialog("Delete \(tunnel.name)?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete tunnel") { store.remove(tunnel); dismiss() }
            Button("Cancel", role: .cancel) {}
        }
        .onAppear { polling = true; updateRuntime() }
        .onDisappear { polling = false }
        .onReceive(timer) { _ in if polling { updateRuntime() } }
    }

    private func updateRuntime() {
        tunnel.getRuntimeTunnelConfiguration { configuration in
            DispatchQueue.main.async { runtime = configuration }
        }
    }
}

private struct TVImportView: View {
    @EnvironmentObject var store: TVTunnelStore
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var receiver = ConfigurationReceiver()
    @StateObject private var download = HTTPSConfigurationDownload()
    var replacing: TunnelContainer?
    @State private var name = ""
    @State private var url = ""
    @State private var result = ""
    @State private var localImport = false

    var body: some View {
        List {
            if let tunnel = replacing {
                Section {
                    Text("Replace “\(tunnel.name)” by importing its complete configuration with the desired name. An active tunnel restarts after saving.")
                }
            }
            Section("Import from a nearby browser") {
                if localImport {
                    Text(receiver.message)
                    ForEach(receiver.addresses, id: \.self) { address in
                        HStack(spacing: 36) {
                            if let code = qrCode(address) {
                                Image(uiImage: code).interpolation(.none).resizable().frame(width: 240, height: 240)
                                    .padding(18).background(.white).accessibilityLabel("Scan to open local import")
                            }
                            Text(address).font(.system(size: 25, design: .monospaced))
                        }
                    }
                    Text("Use a trusted local network: this transfer uses unencrypted HTTP. Anyone with this address can submit a configuration while import is open. The address expires in five minutes.")
                    Button("Close local import") { closeLocalImport() }
                } else {
                    Button("Open local import") {
                        receiver.onImport = { name, config, completion in
                            store.save(name: name, text: config, replacing: replacing, completion: completion)
                        }
                        localImport = true
                        receiver.start()
                    }
                }
            }
            Section("Import from HTTPS URL") {
                TextField("Tunnel name", text: $name)
                TextField("https://example.com/tunnel.conf", text: $url)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button(download.isLoading ? "Downloading…" : "Download and save") {
                    closeLocalImport()
                    result = ""
                    download.start(url: url) { outcome in
                        switch outcome {
                        case .success(let config):
                            store.save(name: name, text: config, replacing: replacing) { error in
                                result = error ?? "Tunnel saved. Return to the tunnel list to connect."
                            }
                        case .failure: result = "Unable to download configuration. Use an HTTPS URL serving a valid .conf file of at most 64 KB."
                        }
                    }
                }
                .disabled(download.isLoading || store.isSaving || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                Text("The URL must serve the configuration directly. Use a server you trust with your tunnel’s private key.")
                if !result.isEmpty { Text(result) }
            }
        }
        .navigationTitle(replacing == nil ? "Add tunnel" : "Replace tunnel")
        .onAppear { name = replacing?.name ?? "" }
        .onDisappear { closeLocalImport(); download.cancel() }
        .onChange(of: scenePhase) { _, phase in
            if phase != .active { closeLocalImport(); download.cancel() }
        }
    }

    private func qrCode(_ address: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(address.utf8)
        guard let output = filter.outputImage,
              let image = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: image)
    }

    private func closeLocalImport() {
        receiver.stop()
        receiver.onImport = nil
        localImport = false
    }
}

private struct TVLogView: View {
    @State private var entries: [String] = []
    @State private var helper: LogViewHelper?
    @State private var fetching = false
    private let timer = Timer.publish(every: 3, on: .main, in: .common).autoconnect()

    var body: some View {
        List {
            if entries.isEmpty { Text("No log entries available.") }
            ForEach(Array(entries.enumerated()), id: \.offset) { _, entry in
                Text(entry).font(.system(size: 22, design: .monospaced))
            }
        }
        .navigationTitle("WireGuard log")
        .onAppear { helper = LogViewHelper(logFilePath: FileManager.logFileURL?.path); fetch() }
        .onDisappear { helper = nil }
        .onReceive(timer) { _ in fetch() }
    }

    private func fetch() {
        guard let helper = helper, !fetching else { return }
        fetching = true
        helper.fetchLogEntriesSinceLastFetch { newEntries in
            entries = Array((entries + newEntries.map { $0.text() }).suffix(500))
            fetching = false
        }
    }
}
