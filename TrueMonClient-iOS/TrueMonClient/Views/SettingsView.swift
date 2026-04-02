import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var data: DataModule
    @State private var passphrase: String = ""
    @State private var portString: String = ""
    @FocusState private var focusedField: Field?

    private enum Field { case host, port, key }

    var body: some View {
        Form {
            // Connection
            Section {
                TextField("Server Host", text: $data.serverHost)
                    .textContentType(.URL)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(AppTheme.text)
                    .focused($focusedField, equals: .host)
                    .submitLabel(.next)
                    .onSubmit { focusedField = .port }

                TextField("Port", text: $portString)
                    .keyboardType(.numberPad)
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(AppTheme.text)
                    .focused($focusedField, equals: .port)
                    .onChange(of: portString) { newValue in
                        if let p = UInt16(newValue) {
                            data.serverPort = p
                        }
                    }

                SecureField("Shared Key", text: $passphrase)
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(AppTheme.text)
                    .focused($focusedField, equals: .key)
                    .submitLabel(.done)
                    .onSubmit { focusedField = nil }
                    .onChange(of: passphrase) { newValue in
                        data.savePassphrase(newValue)
                    }
            } header: {
                Label("CONNECTION", systemImage: "network")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .tracking(2)
                    .foregroundColor(AppTheme.cyan)
            }

            // Connect / Disconnect
            Section {
                Button {
                    if data.connectionState == .connected {
                        data.disconnect()
                    } else {
                        data.connect()
                    }
                } label: {
                    HStack {
                        Spacer()
                        if data.connectionState == .connected {
                            Label("DISCONNECT", systemImage: "xmark.circle")
                                .foregroundColor(AppTheme.critical)
                        } else if data.connectionState == .connecting {
                            ProgressView()
                                .tint(AppTheme.cyan)
                            Text("Connecting...")
                                .foregroundColor(AppTheme.cyan)
                        } else {
                            Label("CONNECT", systemImage: "play.circle")
                                .foregroundColor(AppTheme.lime)
                        }
                        Spacer()
                    }
                    .font(.system(.body, design: .monospaced).weight(.bold))
                }

                HStack {
                    Text("Status")
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(AppTheme.textDim)
                    Spacer()
                    Circle()
                        .fill(statusColor)
                        .frame(width: 8, height: 8)
                        .shadow(color: statusColor.opacity(0.5), radius: 4)
                    Text(data.connectionState.label)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(AppTheme.textDim)
                }

                if let error = data.errorMessage {
                    Text(error)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(AppTheme.critical)
                }
            }

            // Alert Thresholds
            Section {
                VStack(alignment: .leading) {
                    Text("CPU Temp Threshold: \(Int(data.tempThreshold))°C")
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(AppTheme.text)
                    Slider(value: $data.tempThreshold, in: 40...96, step: 1)
                        .tint(AppTheme.orange)
                }

                Toggle("CPU Usage Alerts (>95%)", isOn: $data.cpuAlertEnabled)
                    .font(.system(.body, design: .monospaced))
                    .tint(AppTheme.cyan)

                Toggle("Memory Usage Alerts (>95%)", isOn: $data.memoryAlertEnabled)
                    .font(.system(.body, design: .monospaced))
                    .tint(AppTheme.cyan)
            } header: {
                Label("ALERT THRESHOLDS", systemImage: "bell.badge")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .tracking(2)
                    .foregroundColor(AppTheme.orange)
            }

            // About
            Section {
                HStack {
                    Text("TrueMonClient")
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(AppTheme.textDim)
                    Spacer()
                    Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—")
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(AppTheme.textDim)
                }
                if let stats = data.stats {
                    if let hostname = stats.hostname {
                        HStack {
                            Text("Server")
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(AppTheme.textDim)
                            Spacer()
                            Text(hostname)
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(AppTheme.cyan)
                        }
                    }
                    if let version = stats.version {
                        HStack {
                            Text("TrueMonitor")
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(AppTheme.textDim)
                            Spacer()
                            Text(version)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(AppTheme.textDim)
                        }
                    }
                }
            } header: {
                Label("ABOUT", systemImage: "info.circle")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .tracking(2)
                    .foregroundColor(AppTheme.purple)
            }
        }
        .scrollContentBackground(.hidden)
        .background {
            AppTheme.backgroundGradient.ignoresSafeArea()
        }
        .onTapGesture {
            focusedField = nil
        }
        .toolbar {
            ToolbarItemGroup(placement: .keyboard) {
                Spacer()
                Button("Done") { focusedField = nil }
                    .font(.system(.body, design: .monospaced).weight(.bold))
            }
        }
        .onAppear {
            portString = String(data.serverPort)
            passphrase = data.loadPassphrase() ?? "truemonitor"
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    if data.connectionState == .connected {
                        data.disconnect()
                    } else {
                        data.connect()
                    }
                } label: {
                    if data.connectionState == .connecting {
                        ProgressView().tint(AppTheme.cyan)
                    } else if data.connectionState == .connected {
                        Label("Disconnect", systemImage: "xmark.circle.fill")
                            .foregroundStyle(AppTheme.critical)
                    } else {
                        Label("Connect", systemImage: "play.circle.fill")
                            .foregroundStyle(AppTheme.lime)
                    }
                }
            }
        }
    }

    private var statusColor: Color {
        switch data.connectionState {
        case .connected:    return AppTheme.lime
        case .connecting:   return AppTheme.gold
        case .disconnected: return AppTheme.textDim
        case .failed:       return AppTheme.critical
        }
    }
}
