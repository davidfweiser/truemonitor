import SwiftUI

struct SettingsView: View {
    @EnvironmentObject var service: MonitorService
    @State private var passphrase: String = ""
    @State private var portString: String = ""

    var body: some View {
        Form {
            // Connection
            Section {
                TextField("Server Host", text: $service.serverHost)
                    .textContentType(.URL)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
                    .foregroundColor(AppTheme.text)

                TextField("Port", text: $portString)
                    .keyboardType(.numberPad)
                    .foregroundColor(AppTheme.text)
                    .onChange(of: portString) { newValue in
                        if let p = UInt16(newValue) {
                            service.serverPort = p
                        }
                    }

                SecureField("Shared Key", text: $passphrase)
                    .foregroundColor(AppTheme.text)
                    .onChange(of: passphrase) { newValue in
                        service.savePassphrase(newValue)
                    }
            } header: {
                Text("Connection")
            }

            // Connect / Disconnect
            Section {
                Button {
                    if service.connectionState == .connected {
                        service.disconnect()
                    } else {
                        service.connect()
                    }
                } label: {
                    HStack {
                        Spacer()
                        if service.connectionState == .connected {
                            Label("Disconnect", systemImage: "xmark.circle")
                                .foregroundColor(AppTheme.critical)
                        } else if service.connectionState == .connecting {
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
                    Text(service.connectionState.label)
                        .font(.caption)
                        .foregroundColor(AppTheme.textDim)
                }

                if let error = service.errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(AppTheme.critical)
                }
            }

            // Alert Thresholds
            Section {
                VStack(alignment: .leading) {
                    Text("CPU Temp Threshold: \(Int(service.tempThreshold))°C")
                        .foregroundColor(AppTheme.text)
                    Slider(value: $service.tempThreshold, in: 40...96, step: 1)
                        .tint(AppTheme.accent)
                }

                Toggle("CPU Usage Alerts (>95%)", isOn: $service.cpuAlertEnabled)
                    .tint(AppTheme.accent)

                Toggle("Memory Usage Alerts (>95%)", isOn: $service.memoryAlertEnabled)
                    .tint(AppTheme.accent)
            } header: {
                Text("Alert Thresholds")
            }

            // About
            Section {
                HStack {
                    Text("Version")
                        .foregroundColor(AppTheme.textDim)
                    Spacer()
                    Text("1.0")
                        .foregroundColor(AppTheme.textDim)
                }
                if let stats = service.stats {
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
                            Text("TrueNAS Version")
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
        .onAppear {
            portString = String(service.serverPort)
            passphrase = service.loadPassphrase() ?? "truemonitor"
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    if service.connectionState == .connected {
                        service.disconnect()
                    } else {
                        service.connect()
                    }
                } label: {
                    if service.connectionState == .connecting {
                        ProgressView().tint(AppTheme.accent)
                    } else if service.connectionState == .connected {
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
        switch service.connectionState {
        case .connected:    return AppTheme.good
        case .connecting:   return AppTheme.warning
        case .disconnected: return AppTheme.textDim
        case .failed:       return AppTheme.critical
        }
    }
}
