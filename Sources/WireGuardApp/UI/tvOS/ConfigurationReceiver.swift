// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import Combine
import Foundation
import Network

/// An explicitly opened, short-lived LAN import session. Configurations are never written to disk.
final class ConfigurationReceiver: ObservableObject {
    @Published private(set) var addresses: [String] = []
    @Published private(set) var message = "Starting local import…"
    private var listener: NWListener?
    private var connections: [UUID: NWConnection] = [:]
    private var expiry: Timer?
    private var token = ""
    var onImport: ((String, String, @escaping (String?) -> Void) -> Void)?

    func start() {
        stop()
        token = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        do {
            let listener = try NWListener(using: .tcp)
            self.listener = listener
            listener.newConnectionHandler = { [weak self] connection in self?.accept(connection) }
            listener.stateUpdateHandler = { [weak self] state in
                guard let self = self, self.listener === listener else { return }
                switch state {
                case .ready:
                    guard let port = listener.port else { return }
                    self.addresses = Self.localAddresses().map { "http://\($0):\(port)/\(self.token)" }
                    self.message = self.addresses.isEmpty ? "No local network address found. Connect to Wi-Fi or Ethernet and reopen import." : "Open this address on a phone or computer on the same network."
                case .failed: self.stop(); self.message = "Local import failed. Check local network access in Settings and try again."
                default: break
                }
            }
            listener.start(queue: .main)
            expiry = Timer.scheduledTimer(withTimeInterval: 300, repeats: false) { [weak self] _ in
                self?.stop()
                self?.message = "Import session expired. Close and reopen to start a new session."
            }
        } catch {
            message = "Unable to start local import. Try again."
        }
    }

    func stop() {
        expiry?.invalidate()
        expiry = nil
        listener?.stateUpdateHandler = nil
        listener?.cancel()
        listener = nil
        connections.values.forEach { $0.cancel() }
        connections.removeAll()
        addresses = []
        token = ""
    }

    private func accept(_ connection: NWConnection) {
        guard connections.count < 4 else { connection.cancel(); return }
        let id = UUID()
        connections[id] = connection
        connection.start(queue: .main)
        DispatchQueue.main.asyncAfter(deadline: .now() + 20) { [weak self, weak connection] in
            connection?.cancel()
            self?.connections.removeValue(forKey: id)
        }
        receive(connection, id: id, buffer: Data())
    }

    private func receive(_ connection: NWConnection, id: UUID, buffer: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 8192) { [weak self] data, _, complete, error in
            guard let self = self, self.connections[id] != nil else { return }
            var buffer = buffer
            buffer.append(data ?? Data())
            guard buffer.count <= 73728 else { self.respond(connection, id: id, code: 413, body: "Configuration too large."); return }
            if let boundary = buffer.range(of: Data("\r\n\r\n".utf8)) {
                guard boundary.lowerBound <= 8192, let headers = String(data: buffer[..<boundary.lowerBound], encoding: .utf8) else {
                    self.respond(connection, id: id, code: 400, body: "Invalid request."); return
                }
                let lines = headers.components(separatedBy: "\r\n")
                let request = (lines.first ?? "").split(separator: " ")
                guard request.count == 3, request[1] == "/\(self.token)", !self.token.isEmpty else {
                    self.respond(connection, id: id, code: 404, body: "Import session not found."); return
                }
                if request[0] == "GET" {
                    self.respond(connection, id: id, code: 200, body: Self.page, html: true); return
                }
                let fields = lines.dropFirst().compactMap { line -> (String, String)? in
                    guard let colon = line.firstIndex(of: ":") else { return nil }
                    return (line[..<colon].lowercased(), line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces))
                }
                let lengths = fields.filter { $0.0 == "content-length" }
                guard request[0] == "POST", lengths.count == 1, let length = Int(lengths[0].1), (1...65536).contains(length), !fields.contains(where: { $0.0 == "transfer-encoding" }) else {
                    self.respond(connection, id: id, code: 400, body: "Invalid request length."); return
                }
                let body = buffer[boundary.upperBound...]
                if body.count >= length {
                    guard let object = try? JSONSerialization.jsonObject(with: Data(body.prefix(length))) as? [String: String],
                          let name = object["name"], let config = object["config"], let onImport = self.onImport else {
                        self.respond(connection, id: id, code: 400, body: "Provide a tunnel name and a .conf file."); return
                    }
                    onImport(name, config) { [weak self] error in
                        guard let self = self, self.connections[id] != nil else { return }
                        self.respond(connection, id: id, code: error == nil ? 200 : 400, body: error ?? "Tunnel saved. You can close this page.")
                        self.message = error == nil ? "Tunnel saved. Close import to connect." : "Import failed. Correct the configuration and try again."
                    }
                    return
                }
            } else if buffer.count > 8192 {
                self.respond(connection, id: id, code: 413, body: "Headers too large."); return
            }
            if complete || error != nil {
                connection.cancel(); self.connections.removeValue(forKey: id)
            } else {
                self.receive(connection, id: id, buffer: buffer)
            }
        }
    }

    private func respond(_ connection: NWConnection, id: UUID, code: Int, body: String, html: Bool = false) {
        let bytes = Data(body.utf8)
        let headers = "HTTP/1.1 \(code) \(code == 200 ? "OK" : "Error")\r\nContent-Type: \(html ? "text/html" : "text/plain"); charset=utf-8\r\nContent-Length: \(bytes.count)\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'\r\n\r\n"
        connection.send(content: Data(headers.utf8) + bytes, completion: .contentProcessed { [weak self] _ in
            connection.cancel()
            self?.connections.removeValue(forKey: id)
        })
    }

    private static func localAddresses() -> [String] {
        var interfaces: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&interfaces) == 0 else { return [] }
        defer { freeifaddrs(interfaces) }
        var result: [String] = []
        var current = interfaces
        while let interface = current?.pointee {
            defer { current = interface.ifa_next }
            guard String(cString: interface.ifa_name).hasPrefix("en"), let address = interface.ifa_addr,
                  address.pointee.sa_family == UInt8(AF_INET), interface.ifa_flags & UInt32(IFF_UP) != 0 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                result.append(String(cString: host))
            }
        }
        return Array(Set(result)).sorted()
    }

    private static let page = #"""
    <!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>WireGuard Apple TV import</title><style>body{font:18px system-ui;max-width:640px;margin:50px auto;padding:20px;background:#151515;color:white}input,textarea,button{display:block;box-sizing:border-box;width:100%;font:inherit;padding:12px;margin:12px 0}textarea{height:240px}button{cursor:pointer}p{line-height:1.5}</style>
    <h1>WireGuard for Apple TV</h1><p>Import or replace a tunnel with a WireGuard .conf file. This local connection is unencrypted; use only a trusted network. The session expires after five minutes.</p>
    <form id="form"><label>Tunnel name<input id="name" maxlength="128" required autocomplete="off"></label><label>Configuration file<input id="file" type="file" accept=".conf,text/plain"></label><label>Or paste configuration<textarea id="config" spellcheck="false" autocomplete="off" placeholder="[Interface]"></textarea></label><button>Save tunnel on Apple TV</button></form><p id="result" role="status"></p>
    <script>
    const file=document.getElementById('file'),name=document.getElementById('name'),config=document.getElementById('config'),result=document.getElementById('result');
    file.onchange=async()=>{if(!file.files[0])return;if(file.files[0].size>60000){result.textContent='File is too large.';return;}config.value=await file.files[0].text();if(!name.value)name.value=file.files[0].name.replace(/\.conf$/i,'');};
    document.getElementById('form').onsubmit=async e=>{e.preventDefault();const button=e.target.querySelector('button');button.disabled=true;try{const response=await fetch(location.pathname,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name.value,config:config.value})});result.textContent=await response.text();if(response.ok){config.value='';file.value='';}}catch{result.textContent='Connection failed. Check that import is still open on Apple TV.';}finally{button.disabled=false;}};
    </script></html>
    """#
}

/// Uses an ephemeral session, bounds memory, and forbids redirects to unencrypted URLs.
final class HTTPSConfigurationDownload: NSObject, ObservableObject, URLSessionDataDelegate {
    @Published private(set) var isLoading = false
    private var session: URLSession?
    private var data = Data()
    private var completion: ((Result<String, Error>) -> Void)?
    private let invalidResponse = NSError(domain: "WireGuardImport", code: 1)

    func start(url string: String, completion: @escaping (Result<String, Error>) -> Void) {
        cancel()
        guard let url = URL(string: string.trimmingCharacters(in: .whitespacesAndNewlines)), url.scheme?.lowercased() == "https", url.host != nil, url.user == nil, url.password == nil else {
            completion(.failure(invalidResponse)); return
        }
        self.completion = completion
        data = Data()
        isLoading = true
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.timeoutIntervalForRequest = 20
        config.timeoutIntervalForResource = 30
        let session = URLSession(configuration: config, delegate: self, delegateQueue: .main)
        self.session = session
        session.dataTask(with: url).resume()
    }

    func cancel() {
        session?.invalidateAndCancel()
        session = nil
        completion = nil
        data = Data()
        isLoading = false
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(session === self.session && request.url?.scheme?.lowercased() == "https" ? request : nil)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard session === self.session, let response = response as? HTTPURLResponse, response.statusCode == 200, response.expectedContentLength <= 65536 else {
            completionHandler(.cancel); return
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive chunk: Data) {
        guard session === self.session, data.count + chunk.count <= 65536 else { dataTask.cancel(); return }
        data.append(chunk)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard session === self.session else { return }
        let completion = self.completion
        let result: Result<String, Error>
        if error == nil, let text = String(data: data, encoding: .utf8), !text.isEmpty {
            result = .success(text)
        } else {
            result = .failure(invalidResponse)
        }
        cancel()
        completion?(result)
    }
}
