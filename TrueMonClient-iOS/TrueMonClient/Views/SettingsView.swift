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
                    .foregroundColor(AppTheme.text)
                    .focused($focusedField, equals: .host)
                    .submitLabel(.next)
                    .onSubmit { focusedField = .port }

                TextField("Port", text: $portString)
                    .keyboardType(.numberPad)
                    .foregroundColor(AppTheme.text)
                    .focused($focusedField, equals: .port)
                    .onChange(of: portString) { newValue in
                        if let p = UInt16(newValue) {
                            data.serverPort = p
                        }
                    }

                SecureField("Shared Key", text: $passphrase)
                    .foregroundColor(AppTheme.text)
                    .focused($focusedField, equals: .key)
                    .submitLabel(.done)
                    .onSubmit { focusedField = nil }
                    .onChange(of: passphrase) { newValue in
                        data.savePassphrase(newValue)
                    }
            } header: {
                Text("Connection")
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
                            Label("Disconnect", systemImage: "xmark.circle")
                                .foregroundColor(AppTheme.critical)
                        } else if data.connectionState == .connecting {
                            ProgressView()
                                .tint(AppTheme.accent)
                            Text("Connecting...")
                                .foregroundColor(AppTheme.accent)
                        } else {
                            Label("Connect", systemImage: "play.circle")
                                .foregroundColor(AppTheme.good)
                        }
                        Spacer()
                    }
                }

                HStack {
                    Text("Status")
                        .foregroundColor(AppTheme.textDim)
                    Spacer()
                    Circle()
                        .fill(statusColor)
                        .frame(width: 8, height: 8)
                    Text(data.connectionState.label)
                        .font(.caption)
                        .foregroundColor(AppTheme.textDim)
                }

                if let error = data.errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(AppTheme.critical)
                }
            }

            // Alert Thresholds
            Section {
                VStack(alignment: .leading) {
                    Text("CPU Temp Threshold: \(Int(data.tempThreshold))°C")
                        .foregroundColor(AppTheme.text)
                    Slider(value: $data.tempThreshold, in: 40...96, step: 1)
                        .tint(AppTheme.accent)
                }

                Toggle("CPU Usage Alerts (>95%)", isOn: $data.cpuAlertEnabled)
                    .tint(AppTheme.accent)

                Toggle("Memory Usage Alerts (>95%)", isOn: $data.memoryAlertEnabled)
                    .tint(AppTheme.accent)
            } header: {
                Text("Alert Thresholds")
            }

            // About
            Section {
                HStack {
                    Text("TrueMonClient")
                        .foregroundColor(AppTheme.textDim)
                    Spacer()
                    Text(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—")
                        .foregroundColor(AppTheme.textDim)
                }
                if let stats = data.stats {
                    if let hostname = stats.hostname {
                        HStack {
                            Text("Server")
                                .foregroundColor(AppTheme.textDim)
                            Spacer()
                            Text(hostname)
                                .foregroundColor(AppTheme.textDim)
                        }
                    }
                    if let version = stats.version {
                        HStack {
                            Text("TrueMonitor")
                                .foregroundColor(AppTheme.textDim)
                            Spacer()
                            Text(version)
                                .font(.caption)
                                .foregroundColor(AppTheme.textDim)
                        }
                    }
                }
            } header: {
                Text("About")
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
                    .fontWeight(.semibold)
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
                        ProgressView().tint(AppTheme.accent)
                    } else if data.connectionState == .connected {
                        Label("Disconnect", systemImage: "xmark.circle.fill")
                            .foregroundStyle(AppTheme.critical)
                    } else {
                        Label("Connect", systemImage: "play.circle.fill")
                            .foregroundStyle(AppTheme.good)
                    }
                }
            }
        }
    }

    private var statusColor: Color {
        switch data.connectionState {
        case .connected:    return AppTheme.good
        case .connecting:   return AppTheme.warning
        case .disconnected: return AppTheme.textDim
        case .failed:       return AppTheme.critical
        }
    }
}
