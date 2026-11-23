import Cocoa
import SwiftUI
import UniformTypeIdentifiers

// Compiled into the executable so an already-running older process cannot report a newly installed version.
let appVersion = "1.2.3"
let appBuild = "6"
let appVersionLabel = "v\(appVersion) (build \(appBuild))"

func replace(_ text: String, _ pattern: String, _ transform: (String) -> String) -> String {
    guard let regex = try? NSRegularExpression(pattern: pattern) else { return text }
    var result = text
    for match in regex.matches(in: text, range: NSRange(text.startIndex..., in: text)).reversed() {
        if let range = Range(match.range, in: result) { result.replaceSubrange(range, with: transform(String(result[range]))) }
    }
    return result
}
final class Cleaner {
    var counts = [0, 0, 0]
    var category = 0
    func tracked(_ text: String, _ pattern: String, _ transform: (String) -> String) -> String {
        replace(text, pattern) { value in
            let result = transform(value)
            if result != value { self.counts[self.category] += 1 }
            return result
        }
    }
    // Patterns capture only the sensitive value; surrounding syntax stays byte-for-byte intact.
    func redactValues(_ text: String, _ pattern: String) -> String {
        let regex = try! NSRegularExpression(pattern: pattern)
        var result = text
        for match in regex.matches(in: text, range: NSRange(text.startIndex..., in: text)).reversed() {
            guard let range = Range(match.range(withName: "value"), in: result) else { continue }
            if result[range] != "[REDACTED]" {
                result.replaceSubrange(range, with: "[REDACTED]")
                counts[2] += 1
            }
        }
        return result
    }
    func redactCredentialLine(_ line: String) -> String {
        // Ignore comments/descriptions and negative commands, which contain no configured secret.
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("!") || trimmed.hasPrefix("#") || trimmed.lowercased().hasPrefix("description ") || trimmed.lowercased().hasPrefix("no ") { return line }
        if trimmed.range(of: #"(?i)^password\h+encryption\h+aes\h*$"#, options:.regularExpression) != nil { return line }
        if trimmed.range(of: #"(?i)^(?:password (?:strength|policy|minimum-length|min-length)|key chain |authentication (?:key-chain|mode) )"#, options:.regularExpression) != nil { return line }
        let token = #"(?:"[^"\r\n]*"|'[^'\r\n]*'|[^ \t\r\n]+)"#
        let value = "(?<value>" + token + ")"
        var result = line
        // Commands with extra fields before the value must be handled before generic keywords.
        let specialPatterns = [
            #"(?i)\b(?:ntp\h+)?authentication-key\h+\d+\h+(?:md5|sha1|sha2|cmac-aes-128|hmac-sha1|hmac-sha2-256)\h+(?:(?:clear|encrypted|plain|hash)\h+)?"# + value,
            #"(?i)\bpre-shared-key\h+address\h+\S+(?:\h+\S+)?\h+key\h+(?:(?:0|6|7)\h+)?"# + value,
            #"(?i)\bpre-shared-key\h+(?:(?:local|remote)\h+)?(?:(?:0|6|7|hex|line)\h+)?"# + value,
            #"(?i)\b(?:ip\h+ospf|ospfv3)\h+message-digest-key\h+\d+\h+(?:(?:0|3|7)\h+)?md5\h+(?:(?:0|3|7)\h+)?"# + value,
            #"(?i)^\h*(?:standby|vrrp)\h+(?:\d+\h+)?authentication\h+(?:text\h+)?(?!(?:md5|key-chain)\b)"# + value,
            #"(?i)\b(?:radius-server|tacacs-server)\h+host\h+\S+[^\r\n]*?\h+key\h+(?:(?:0|6|7)\h+)?"# + value,
            #"(?i)^\h*(?:ldap-login-password|radius-common-pw|passwd|enable\h+passwd)\h+"# + value,
            #"(?i)\blicense\h+smart\h+(?:register|trust)\h+idtoken\h+"# + value,
            #"(?i)^\h*key\h+config-key\h+password-encrypt\h+"# + value
        ]
        for pattern in specialPatterns {
            let regex = try! NSRegularExpression(pattern:pattern)
            if regex.firstMatch(in:line,range:NSRange(line.startIndex...,in:line)) != nil {
                return redactValues(line,pattern)
            }
        }
        let patterns = [
            // IOS/IOS-XE/NX-OS and ASA password/secret commands, including type markers.
            #"(?i)\b(?:password|secret|key-string|pre-shared-key|authentication-key|encryption-key|encrypted-password|wpa-psk|pac-key)\h+(?:(?:level\h+\d+|(?:0|5|6|7|8|9)|sha512|sha256|md5|pbkdf2|scrypt|clear|encrypted|ascii|hex)\h+)*"# + value,
            #"(?i)\bsnmp-server\h+community\h+(?:(?:0|6|7)\h+)?"# + value,
            #"(?i)\b(?:tacacs-server|radius-server)\h+key\h+(?:(?:0|6|7)\h+)?"# + value,
            #"(?i)\bcrypto\h+isakmp\h+key\h+(?:(?:0|6|7)\h+)?"# + value,
            // RADIUS private-server keys occur after the address and optional ports/timeouts.
            #"(?i)\bserver-private\h+\S+(?:\h+[^\r\n]*?)?\h+key\h+(?:(?:0|6|7)\h+)?"# + value,
            // Server and key-chain subcommands; a bare 'key <id>' selects a key-chain entry.
            #"(?i)^\h*key\h+(?:(?:0|6|7)\h+)?"# + value + #"(?=\h|$)"#,
            #"(?i)\bsnmp-server\h+host\h+\S+\h+(?:(?:traps|informs)\h+)?version\h+(?:1|2c)\h+"# + value,
            #"(?i)\bauth\h+(?:md5|sha|sha-1|sha-224|sha-256|sha-384|sha-512|sha256|sha512)\h+(?:(?:0|6|7)\h+)?"# + value,
            #"(?i)\bpriv\h+(?:des|3des|aes(?:\h+(?:128|192|256))?)\h+(?:(?:0|6|7)\h+)?"# + value,
            #"(?i)\b(?:https?|ftp)://[^\s/:@]+:(?<value>[^\s/@]+)@"#
        ]
        for pattern in patterns {
            // Numeric-only key commands are identifiers, not passwords.
            if pattern.hasPrefix(#"(?i)^\h*key"#), trimmed.range(of: #"(?i)^key\h+\d+$"#, options:.regularExpression) != nil { continue }
            result = redactValues(result, pattern)
        }
        if trimmed.range(of: #"(?i)^snmp-server\h+host\h+"#, options:.regularExpression) != nil {
            // v1 is implicit without a version clause; v3 uses a username, not a community.
            let hostPrefix = #"(?i)^\h*snmp-server\h+host\h+(?:vrf\h+\S+\h+)?\S+\h+(?:vrf\h+\S+\h+)?(?:(?:traps|informs)\h+)?"#
            if trimmed.range(of: #"(?i)\bversion\h+3\b"#, options:.regularExpression) == nil {
                result = redactValues(result, hostPrefix + #"(?:version\h+(?:1|2c)\h+)?"# + value)
            }
        }
        return result
    }
    func stripIdentity(_ input: String, options: IdentityOptions = IdentityOptions()) -> String {
        let lines = input.components(separatedBy: "\n")
        var output: [String] = []
        var delimiter: String?
        for line in lines {
            if let end = delimiter {
                if line.contains(end) { delimiter = nil }
                continue
            }
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if options.banners, let range = trimmed.range(of: #"(?i)^banner\h+\S+\h+"#, options:.regularExpression) {
                let payload = String(trimmed[range.upperBound...])
                if !payload.isEmpty {
                    let end = payload.hasPrefix("^") && payload.count >= 2 ? String(payload.prefix(2)) : String(payload.prefix(1))
                    if !payload.dropFirst(end.count).contains(end) { delimiter = end }
                }
                continue
            }
            if options.location, trimmed.range(of: #"(?i)^(?:snmp-server\h+(?:location|contact|chassis-id)|location|system\h+location)\b"#,options:.regularExpression) != nil { continue }
            var commands: [String] = []
            if options.domains { commands += [#"ip\h+domain(?:-|\h+)(?:name|list)(?:\h+vrf\h+\S+)?"#, "domain-name"] }
            if options.descriptions { commands += ["description"] }
            if options.location { commands += [#"snmp-server\h+(?:name|sysname)"#] }
            var cleaned = line
            if !commands.isEmpty {
                let regex = try! NSRegularExpression(pattern: #"(?i)^(\h*(?:"# + commands.joined(separator:"|") + #")\h+)([^\r\n]+)"#)
                if let match = regex.firstMatch(in:line,range:NSRange(line.startIndex...,in:line)), let r = Range(match.range(at:2),in:line) {
                    cleaned.replaceSubrange(r,with:"[REDACTED]")
                }
            }
            output.append(cleaned)
        }
        var result = output.joined(separator:"\n")
        if options.serials {
            // Find values only in explicit serial/UDI fields, then redact repeats of those values.
            let pattern = #"(?im)(?:\b(?:processor board id|(?:system |chassis |device )?serial(?:[- ]number| no\.?)|license\h+udi\h+pid\h+\S+\h+sn)\h*[:=]?\h+|\bSN\h*:\h*)(?<serial>[A-Za-z0-9][A-Za-z0-9._/-]*)"#
            let regex = try! NSRegularExpression(pattern:pattern)
            let ns = result as NSString
            let serials = Set(regex.matches(in:result,range:NSRange(location:0,length:ns.length)).map { ns.substring(with:$0.range(withName:"serial")) })
            for serial in serials.sorted(by: { $0.count > $1.count }) {
                result = replace(result, #"(?<![A-Za-z0-9._/-])"# + NSRegularExpression.escapedPattern(for:serial) + #"(?![A-Za-z0-9._/-])"#) { _ in "[REDACTED]" }
            }
        }
        return result
    }
    var hosts: [String:String] = [:], ips: [String:String] = [:]
    func alias(_ value: String, host: Bool) -> String {
        if host { if hosts[value] == nil { hosts[value] = "DEVICE_\(hosts.count + 1)" }; return hosts[value]! }
        if ips[value] == nil { ips[value] = "IP_\(ips.count + 1)" }; return ips[value]!
    }
    func clean(_ input: String, hostname: Bool, addresses: Bool, secrets: Bool, scheme: AddressScheme? = nil, marked: Bool = false, identity: Bool = false, identityOptions: IdentityOptions? = nil) -> String {
        counts = [0, 0, 0]
        category = 0
        var text = identityOptions.map { stripIdentity(input,options:$0) } ?? (identity ? stripIdentity(input) : input)
        if hostname {
            let re = try! NSRegularExpression(pattern: "(?im)^\\s*(?:hostname|switchname)\\s+(\\S+)")
            for m in re.matches(in: input, range: NSRange(input.startIndex..., in: input)) {
                if let r = Range(m.range(at: 1), in: input) { _ = alias(String(input[r]), host: true) }
            }
            for name in hosts.keys.sorted(by: { $0.count > $1.count }) {
                text = tracked(text, "(?<![A-Za-z0-9_-])" + NSRegularExpression.escapedPattern(for: name) + "(?![A-Za-z0-9_-])") { _ in self.hosts[name]! }
            }
        }
        category = 2
        if secrets {
            // Keep multiline block headers/terminators while removing their payloads.
            text = redactValues(text, #"(?ms)^\h*-----BEGIN [^\r\n]*PRIVATE KEY-----\r?\n(?<value>.*?)\r?\n\h*-----END [^\r\n]*PRIVATE KEY-----"#)
            text = redactValues(text, #"(?ims)^\h*certificate(?: ca| self-signed)?(?: [^\r\n]+)?\r?\n(?<value>.*?)\r?\n\h*quit\h*$"#)
            text = text.components(separatedBy: "\n").map { redactCredentialLine($0) }.joined(separator: "\n")
        }
        category = 1
        if addresses, let scheme = scheme {
            let result = scheme.transform(text) { self.alias($0, host:false) }
            text = result.0
            counts[1] = result.1
        } else if addresses {
            text = tracked(text, "(?<![\\w.])(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?![\\w.])") { value in
                value.split(separator: ".").allSatisfy { (Int($0) ?? 256) < 256 } ? (marked ? "*" : "") + self.alias(value, host: false) : value
            }
            text = tracked(text, "(?i)(?<![\\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,4}(?:%[a-z0-9_.-]+)?(?![\\w:])") { (marked ? "*" : "") + self.alias($0.lowercased(), host: false) }
        }
        return text
    }
}
func cleanName(_ url: URL) -> String {
    let ext = url.pathExtension
    let stem = url.deletingPathExtension().lastPathComponent
    return stem + "-clean" + (ext.isEmpty ? "" : "." + ext)
}

struct ConfigFile: Identifiable {
    let id = UUID()
    let url: URL
    var original = ""
    var cleaned = ""
    var error: String?
    var counts = [0, 0, 0]
    var outputName: String
    var total: Int { counts.reduce(0,+) }
}
final class Model: ObservableObject {
    @Published var files: [ConfigFile] = []
    @Published var selected: UUID?
    @Published var targeted = false
    @Published var host = true { didSet { saveOptions() } }
    @Published var ip = true { didSet { saveOptions() } }
    @Published var schemeMode = true { didSet { saveOptions() } }
    @Published var mappingNote = ""
    @Published var secret = true { didSet { saveOptions() } }
    @Published var identityOptions = IdentityOptions() { didSet { saveOptions() } }
    @Published var status = "Files stay on this Mac"
    private let defaults: UserDefaults?
    private var restoringOptions = true
    // Tests use an isolated store (or no store); only the app uses standard preferences.
    init(defaults: UserDefaults? = nil) {
        self.defaults = defaults
        func option(_ key: String) -> Bool { defaults?.object(forKey:"cleaning." + key) as? Bool ?? true }
        host = option("hostnames")
        ip = option("addresses")
        schemeMode = option("logicalScheme")
        secret = option("secrets")
        identityOptions = IdentityOptions(banners:option("banners"),location:option("location"),domains:option("domains"),descriptions:option("descriptions"),serials:option("serials"))
        restoringOptions = false
    }
    func resetOptions() {
        restoringOptions = true
        host = true
        ip = true
        schemeMode = true
        secret = true
        identityOptions = IdentityOptions()
        restoringOptions = false
        saveOptions()
        refresh()
    }
    private func saveOptions() {
        guard !restoringOptions, let defaults = defaults else { return }
        let values = ["hostnames":host,"addresses":ip,"logicalScheme":schemeMode,"secrets":secret,
                      "banners":identityOptions.banners,"location":identityOptions.location,"domains":identityOptions.domains,
                      "descriptions":identityOptions.descriptions,"serials":identityOptions.serials]
        for (key,value) in values { defaults.set(value,forKey:"cleaning." + key) }
    }
    enum FolderPurpose: String { case input, output }
    func rememberedFolder(_ purpose: FolderPurpose) -> URL? {
        guard let path = defaults?.string(forKey:"folders." + purpose.rawValue) else { return nil }
        var isDirectory: ObjCBool = false
        guard FileManager.default.fileExists(atPath:path,isDirectory:&isDirectory), isDirectory.boolValue,
              FileManager.default.isReadableFile(atPath:path) else { return nil }
        return URL(fileURLWithPath:path,isDirectory:true)
    }
    func rememberFolder(_ folder: URL, for purpose: FolderPurpose) {
        guard folder.isFileURL else { return }
        defaults?.set(folder.standardizedFileURL.path,forKey:"folders." + purpose.rawValue)
    }
    var ready: [ConfigFile] { files.filter { $0.error == nil } }
    var totals: [Int] { (0..<3).map { index in ready.reduce(0) { $0 + $1.counts[index] } } }
    func add(_ urls: [URL]) {
        for url in urls where url.isFileURL && !files.contains(where: { $0.url == url }) {
            var file = ConfigFile(url:url,outputName:cleanName(url))
            do {
                let attrs = try url.resourceValues(forKeys:[.isRegularFileKey,.fileSizeKey])
                guard attrs.isRegularFile == true, (attrs.fileSize ?? 0) <= 20_000_000 else { throw NSError(domain:"Choose a text file under 20 MB",code:1) }
                let data = try Data(contentsOf:url)
                guard !data.contains(0), let text = String(data:data,encoding:.utf8) ?? String(data:data,encoding:.isoLatin1) else { throw NSError(domain:"Not a readable text configuration",code:1) }
                file.original = text
            } catch { file.error = "Could not read this file. Select a text configuration under 20 MB." }
            files.append(file)
        }
        if selected == nil { selected = files.first?.id }
        refresh()
    }
    func refresh() {
        let cleaner = Cleaner()
        let scheme = ip && schemeMode ? AddressScheme(ready.map { $0.original }) : nil
        mappingNote = scheme?.warning ?? ""
        if host { for file in ready { _ = cleaner.clean(file.original,hostname:true,addresses:false,secrets:false) } }
        var names = Set<String>()
        for index in files.indices {
            guard files[index].error == nil else { continue }
            files[index].cleaned = cleaner.clean(files[index].original,hostname:host,addresses:ip,secrets:secret,scheme:scheme,marked:true,identityOptions:identityOptions)
            files[index].counts = cleaner.counts
            let url = files[index].url
            var name = cleanName(url); var suffix = 2
            while names.contains(name.lowercased()) {
                name = url.deletingPathExtension().lastPathComponent + "-\(suffix)-clean" + (url.pathExtension.isEmpty ? "" : "." + url.pathExtension); suffix += 1
            }
            names.insert(name.lowercased()); files[index].outputName = name
        }
        status = files.isEmpty ? "Files stay on this Mac" : "\(ready.count) ready • \(files.count - ready.count) unreadable"
    }
    func remove(_ id: UUID) {
        files.removeAll { $0.id == id }
        if selected == id { selected = files.first?.id }
        refresh()
    }
    func selectFiles() {
        let panel = NSOpenPanel(); panel.allowsMultipleSelection = true; panel.canChooseDirectories = false
        panel.message = "Choose Cisco configuration text files"
        panel.directoryURL = rememberedFolder(.input)
        if panel.runModal() == .OK {
            if let file = panel.urls.first { rememberFolder(file.deletingLastPathComponent(),for:.input) }
            add(panel.urls)
        }
    }
    func exportText(_ file: ConfigFile) -> String {
        let newline = file.cleaned.contains("\r\n") ? "\r\n" : "\n"
        return [
            "! ANONYMIZED REVIEW COPY — NOT A PRODUCTION CONFIGURATION",
            "! * before an address marks an anonymized value; remove only that leading * to restore IP syntax.",
            "! [REDACTED] replaces a secret. Supply appropriate lab credentials before use.",
            "! Markers block affected address commands only; other commands may still execute if pasted.",
            "! Synthetic addresses may be publicly routable. Validate all addressing and dependencies in an isolated lab.",
            "! IP mode: " + (ip ? (schemeMode ? "logical scheme; masks preserved" : "labels (not valid IP addresses)") : "original addresses retained"),
            "!"
        ].joined(separator:newline) + newline + file.cleaned
    }
    func save() {
        let panel = NSOpenPanel(); panel.canChooseFiles = false; panel.canChooseDirectories = true; panel.canCreateDirectories = true; panel.prompt = "Save clean files"
        panel.message = "Save \(ready.count) clean copies. Existing files will not be overwritten."
        panel.directoryURL = rememberedFolder(.output)
        guard panel.runModal() == .OK, let folder = panel.url else { return }
        var saved: [URL] = []
        do {
            for file in ready {
                var destination = folder.appendingPathComponent(file.outputName); var index = 2
                while FileManager.default.fileExists(atPath:destination.path) {
                    let ext = file.url.pathExtension
                    destination = folder.appendingPathComponent(file.url.deletingPathExtension().lastPathComponent + "-\(index)-clean" + (ext.isEmpty ? "" : "." + ext)); index += 1
                }
                try Data(exportText(file).utf8).write(to:destination,options:.withoutOverwriting)
                saved.append(destination)
                rememberFolder(folder,for:.output)
                if let i = files.firstIndex(where: { $0.id == file.id }) { files[i].outputName = destination.lastPathComponent }
            }
            status = "Saved \(saved.count) clean files to \(folder.lastPathComponent)"
            NSWorkspace.shared.activateFileViewerSelecting(saved)
        } catch {
            status = "Saved \(saved.count) files before an error"
            let alert = NSAlert(); alert.messageText = status; alert.informativeText = error.localizedDescription; alert.runModal()
        }
    }
}

struct DiffInfo {
    let original: [String]
    let cleaned: [String]
    var removed = Set<Int>()
    var inserted = Set<Int>()
    let truncated: Bool
    init(_ before: String, _ after: String) {
        // Bound diff work; exported files always contain the full output.
        let a = before.components(separatedBy:"\n")
        let b = after.components(separatedBy:"\n")
        truncated = a.count > 2000 || b.count > 2000 || before.utf8.count > 200_000 || after.utf8.count > 200_000
        original = Array(String(before.prefix(200_000)).components(separatedBy:"\n").prefix(2000))
        cleaned = Array(String(after.prefix(200_000)).components(separatedBy:"\n").prefix(2000))
        for change in cleaned.difference(from:original) {
            switch change {
            case .remove(let offset, _, _): removed.insert(offset)
            case .insert(let offset, _, _): inserted.insert(offset)
            }
        }
    }
}
struct CodePane: NSViewRepresentable {
    let lines: [String]
    let changed: Set<Int>
    let isOriginal: Bool
    func makeNSView(context: Context) -> NSScrollView {
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.hasHorizontalScroller = true; scroll.autohidesScrollers = true
        let text = NSTextView(); text.isEditable = false; text.isRichText = false
        text.isHorizontallyResizable = true; text.isVerticallyResizable = true
        text.minSize = NSSize(width:0,height:0); text.maxSize = NSSize(width:CGFloat.greatestFiniteMagnitude,height:CGFloat.greatestFiniteMagnitude)
        text.textContainer?.containerSize = NSSize(width:CGFloat.greatestFiniteMagnitude,height:CGFloat.greatestFiniteMagnitude)
        text.textContainer?.widthTracksTextView = false
        text.textContainerInset = NSSize(width:12,height:12)
        text.setAccessibilityLabel(isOriginal ? "Original configuration" : "Cleaned configuration")
        scroll.documentView = text
        return scroll
    }
    func updateNSView(_ scroll: NSScrollView, context: Context) {
        guard let text = scroll.documentView as? NSTextView else { return }
        let rendered = NSMutableAttributedString()
        for (index,line) in lines.enumerated() {
            let marker = changed.contains(index) ? (isOriginal ? "−" : "+") : " "
            let prefix = String(format:"%4d %@  ",index + 1,marker)
            var attrs: [NSAttributedString.Key:Any] = [.font:NSFont.monospacedSystemFont(ofSize:12,weight:.regular),.foregroundColor:NSColor.labelColor]
            if changed.contains(index) { attrs[.backgroundColor] = (isOriginal ? NSColor.systemOrange : NSColor.systemGreen).withAlphaComponent(0.14) }
            let row = NSMutableAttributedString(string:prefix + line + "\n",attributes:attrs)
            row.addAttribute(.foregroundColor,value:NSColor.secondaryLabelColor,range:NSRange(location:0,length:prefix.utf16.count))
            rendered.append(row)
        }
        if text.attributedString() != rendered { text.textStorage?.setAttributedString(rendered); text.scrollToBeginningOfDocument(nil) }
    }
}
struct ReviewView: View {
    let file: ConfigFile
    var body: some View {
        let diff = DiffInfo(file.original,file.cleaned)
        VStack(alignment:.leading,spacing:12) {
            HStack {
                VStack(alignment:.leading,spacing:4) {
                    Text(file.url.lastPathComponent).font(.system(size:20,weight:.medium)).lineLimit(1).truncationMode(.middle)
                    Text("→ " + file.outputName).font(.system(size:12,design:.monospaced)).foregroundColor(.secondary).textSelection(.enabled)
                }
                Spacer()
                Text("\(file.total) replacements").font(.system(size:12,design:.monospaced)).foregroundColor(.secondary)
            }
            HStack(spacing:0) {
                pane("Original",subtitle:"− Replaced lines",lines:diff.original,changes:diff.removed,original:true)
                Divider()
                pane("Cleaned",subtitle:"+ Replacement lines",lines:diff.cleaned,changes:diff.inserted,original:false)
            }.background(Color(nsColor:.textBackgroundColor)).clipShape(RoundedRectangle(cornerRadius:8))
                .overlay(RoundedRectangle(cornerRadius:8).stroke(Color(nsColor:.separatorColor),lineWidth:1))
            if diff.truncated { Text("Preview limited to the first 2,000 lines / 200,000 characters. Export includes the complete file.").font(.system(size:12)).foregroundColor(.secondary) }
        }
    }
    func pane(_ title: String, subtitle: String, lines: [String], changes: Set<Int>, original: Bool) -> some View {
        VStack(alignment:.leading,spacing:0) {
            HStack { Text(title).fontWeight(.medium); Spacer(); Text(subtitle).foregroundColor(.secondary).font(.system(size:11)) }.padding(12)
            Divider()
            CodePane(lines:lines,changed:changes,isOriginal:original)
        }.frame(maxWidth:.infinity)
    }
}
struct ContentView: View {
    @ObservedObject var model: Model
    var body: some View {
        HStack(spacing:0) {
            sidebar.frame(width:256)
            Divider()
            VStack(alignment:.leading,spacing:20) {
                HStack {
                    VStack(alignment:.leading,spacing:4) {
                        Text("Review configurations").font(.system(size:24,weight:.medium))
                        Text(appVersionLabel).font(.system(size:11,design:.monospaced)).foregroundColor(.secondary).textSelection(.enabled)
                    }
                    Spacer()
                    Label("On-device only",systemImage:"lock").font(.system(size:12)).foregroundColor(.secondary)
                }
                options
                if let file = model.files.first(where: { $0.id == model.selected }) {
                    if let error = file.error {
                        empty(title:"Unable to read " + file.url.lastPathComponent,detail:error,icon:"doc.badge.ellipsis")
                    } else { ReviewView(file:file) }
                } else {
                    empty(title:"See what changes before you share",detail:"Add configuration files, choose what to remove, then compare the original and cleaned versions here.",icon:"doc.text.magnifyingglass")
                }
                footer
            }.padding(24).frame(maxWidth:.infinity,maxHeight:.infinity)
        }.frame(minWidth:1040,minHeight:700)
        .onChange(of:model.host) { model.refresh() }
        .onChange(of:model.ip) { model.refresh() }
        .onChange(of:model.schemeMode) { model.refresh() }
        .onChange(of:model.secret) { model.refresh() }
        .onChange(of:model.identityOptions) { model.refresh() }
    }
    var sidebar: some View {
        VStack(alignment:.leading,spacing:16) {
            HStack { Text("Files").font(.system(size:16,weight:.medium)); Spacer(); Text("\(model.files.count)").foregroundColor(.secondary).monospacedDigit() }
            VStack(spacing:12) {
                Image(systemName:"tray.and.arrow.down").font(.system(size:20)).foregroundColor(model.targeted ? Color.accentColor : .secondary)
                Text(model.targeted ? "Release to add files" : "Drop configurations here").font(.system(size:13,weight:.medium))
                Button("Select files…") { model.selectFiles() }.keyboardShortcut("o",modifiers:.command)
                Text("Multiple text files supported").font(.system(size:11)).foregroundColor(.secondary)
            }.frame(maxWidth:.infinity).padding(.vertical,20)
                .background(model.targeted ? Color.accentColor.opacity(0.08) : Color(nsColor:.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius:8))
                .overlay(RoundedRectangle(cornerRadius:8).strokeBorder(model.targeted ? Color.accentColor : Color(nsColor:.separatorColor),style:StrokeStyle(lineWidth:model.targeted ? 2 : 1,dash:[5,4])))
                .onDrop(of:[UTType.fileURL.identifier],isTargeted:$model.targeted) { providers in
                    let group = DispatchGroup(); let lock = NSLock(); var incoming: [(Int,URL)] = []
                    for (index,provider) in providers.enumerated() {
                        group.enter()
                        provider.loadItem(forTypeIdentifier:UTType.fileURL.identifier,options:nil) { item,_ in
                            defer { group.leave() }
                            let url = (item as? URL) ?? (item as? Data).flatMap { URL(dataRepresentation:$0,relativeTo:nil) }
                            if let url = url { lock.lock(); incoming.append((index,url)); lock.unlock() }
                        }
                    }
                    group.notify(queue:.main) { model.add(incoming.sorted { $0.0 < $1.0 }.map { $0.1 }) }
                    return !providers.isEmpty
                }
            if model.files.isEmpty {
                Text("Your file queue is empty").font(.system(size:12)).foregroundColor(.secondary).padding(.top,4)
                Spacer()
            } else {
                List(selection:$model.selected) {
                    ForEach(model.files) { file in
                        HStack(spacing:8) {
                            Image(systemName:file.error == nil ? "doc.text" : "exclamationmark.triangle").foregroundColor(.secondary)
                            VStack(alignment:.leading,spacing:4) {
                                Text(file.url.lastPathComponent).lineLimit(1).truncationMode(.middle)
                                Text(file.error == nil ? "Ready · \(file.total) replacements" : "Unreadable").font(.system(size:11)).foregroundColor(file.error == nil ? Color.secondary : .orange)
                            }
                            Spacer(minLength:0)
                            Button { model.remove(file.id) } label: { Image(systemName:"xmark").font(.system(size:10)) }.buttonStyle(.borderless).help("Remove " + file.url.lastPathComponent).accessibilityLabel("Remove " + file.url.lastPathComponent)
                        }.padding(.vertical,4).tag(file.id).help(file.url.path)
                    }
                }.listStyle(.sidebar)
                Button("Clear queue") { model.files = []; model.selected = nil; model.refresh() }.buttonStyle(.link)
            }
            Divider()
            Text("Originals stay intact").font(.system(size:12,weight:.medium))
            Text("Clean copies use -clean before the file extension").font(.system(size:12)).foregroundColor(.secondary)
        }.padding(16).background(Color(nsColor:.controlBackgroundColor).opacity(0.5))
    }
    var options: some View {
        VStack(alignment:.leading,spacing:12) {
            HStack {
                Text("Remove from every file").font(.system(size:13,weight:.medium))
                Spacer()
                Button("Reset to Defaults") { model.resetOptions() }
                    .controlSize(.small)
                    .help("Enable all cleaning options and use logical IP mapping. Remembered folders stay unchanged.")
            }
            HStack(alignment:.top,spacing:24) {
                option("Hostnames",detail:"Consistent device aliases",value:$model.host)
                VStack(alignment:.leading,spacing:4) {
                    Toggle("IP addresses",isOn:$model.ip).toggleStyle(.checkbox)
                    Picker("Mode",selection:$model.schemeMode) {
                        Text("Logical scheme").tag(true)
                        Text("Labels").tag(false)
                    }.labelsHidden().disabled(!model.ip)
                }.frame(maxWidth:.infinity,alignment:.leading)
                option("Passwords & secrets",detail:"Secret values, keys and certificates",value:$model.secret)
            }
            Text("* = anonymized address · Masks stay valid in logical mode · Remove only the leading * for lab syntax").font(.system(size:11)).foregroundColor(.secondary)
            if !model.mappingNote.isEmpty { Text(model.mappingNote).font(.system(size:11)).foregroundColor(.orange) }
            Divider()
            Text("Additional redaction").font(.system(size:12,weight:.medium))
            LazyVGrid(columns:[GridItem(.flexible(),alignment:.leading),GridItem(.flexible(),alignment:.leading),GridItem(.flexible(),alignment:.leading)],alignment:.leading,spacing:8) {
                Toggle("Remove banners",isOn:$model.identityOptions.banners)
                Toggle("Location & contact",isOn:$model.identityOptions.location)
                Toggle("Domain names",isOn:$model.identityOptions.domains)
                Toggle("Descriptions",isOn:$model.identityOptions.descriptions)
                Toggle("Serial numbers",isOn:$model.identityOptions.serials)
            }.toggleStyle(.checkbox)
            if !model.secret { Label("Credential removal is off — exported files may contain secrets",systemImage:"exclamationmark.triangle").font(.system(size:12)).foregroundColor(.orange) }
        }.padding(16).frame(maxWidth:.infinity,alignment:.leading).background(Color(nsColor:.controlBackgroundColor)).cornerRadius(8)
    }
    func option(_ title: String, detail: String, value: Binding<Bool>) -> some View {
        VStack(alignment:.leading,spacing:4) {
            Toggle(title,isOn:value).toggleStyle(.checkbox)
            Text(detail).font(.system(size:11)).foregroundColor(.secondary).fixedSize(horizontal:false,vertical:true)
        }.frame(maxWidth:.infinity,alignment:.leading)
    }
    func empty(title: String, detail: String, icon: String) -> some View {
        VStack(spacing:16) {
            Image(systemName:icon).font(.system(size:28)).foregroundColor(.secondary)
            Text(title).font(.system(size:20,weight:.medium))
            Text(detail).font(.system(size:13)).foregroundColor(.secondary).multilineTextAlignment(.center).frame(maxWidth:400)
        }.frame(maxWidth:.infinity,maxHeight:.infinity)
    }
    var footer: some View {
        VStack(alignment:.leading,spacing:12) {
            Divider()
            HStack(alignment:.center,spacing:24) {
                VStack(alignment:.leading,spacing:4) {
                    Text("Export summary · \(model.ready.count) files").font(.system(size:13,weight:.medium))
                    Text("\(model.totals[0]) hostname · \(model.totals[1]) IP · \(model.totals[2]) credential replacements").font(.system(size:12,design:.monospaced)).foregroundColor(.secondary)
                }
                Spacer(minLength:0)
                Button("Save clean files…") { model.save() }.buttonStyle(.borderedProminent).controlSize(.large).disabled(model.ready.isEmpty).keyboardShortcut("s",modifiers:.command)
            }
            Text(model.status).font(.system(size:12)).foregroundColor(.secondary).textSelection(.enabled)
            Text("Review before sharing. Unusual secrets and identifying descriptions may remain. Cleaned output is for analysis, not deployment.").font(.system(size:11)).foregroundColor(.secondary).fixedSize(horizontal:false,vertical:true)
        }
    }
}
final class App: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    let model = Model(defaults: .standard)
    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect:NSRect(x:0,y:0,width:1200,height:800),styleMask:[.titled,.closable,.miniaturizable,.resizable],backing:.buffered,defer:false)
        window.title = "Cisco Config Cleaner — " + appVersionLabel; window.minSize = NSSize(width:1040,height:740)
        window.contentView = NSHostingView(rootView:ContentView(model:model))
        let menu = NSMenu(); let appItem = NSMenuItem(); menu.addItem(appItem)
        let appMenu = NSMenu(); appMenu.addItem(withTitle:"Quit Cisco Config Cleaner",action:#selector(NSApplication.terminate(_:)),keyEquivalent:"q"); appItem.submenu = appMenu
        let edit = NSMenuItem(); menu.addItem(edit); let editMenu = NSMenu(title:"Edit"); edit.submenu = editMenu
        editMenu.addItem(withTitle:"Copy",action:#selector(NSText.copy(_:)),keyEquivalent:"c")
        editMenu.addItem(withTitle:"Select All",action:#selector(NSText.selectAll(_:)),keyEquivalent:"a")
        NSApp.mainMenu = menu
        window.center(); window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps:true)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func application(_ sender: NSApplication, openFiles filenames: [String]) { model.add(filenames.map { URL(fileURLWithPath:$0) }) }
}
if CommandLine.arguments.contains("--self-test") {
    let c = Cleaner()
    let input = "hostname edge-1\nusername admin secret 9 HASH\nip address 10.0.0.1 255.255.255.0\nneighbor 10.0.0.1\nipv6 address 2001:db8::1/64\nsnmp-server community PRIVATE RO\ntacacs-server key 7 ABC\n"
    let output = c.clean(input,hostname:true,addresses:true,secrets:true)
    assert(!output.contains("HASH") && !output.contains("PRIVATE") && !output.contains("ABC"))
    assert(!output.contains("edge-1") && !output.contains("10.0.0.1") && !output.contains("2001:db8::1"))
    assert(output.contains("neighbor " + c.ips["10.0.0.1"]!))
    assert(Cleaner().clean(input,hostname:false,addresses:false,secrets:false) == input)
    assert(cleanName(URL(fileURLWithPath:"/tmp/router.cfg")) == "router-clean.cfg")
    assert(c.counts == [1, 4, 3], "Replacement counts must reflect actual substitutions")
    let cases: [(String,String)] = [
        ("username admin privilege 15 secret 9 HASH", "username admin privilege 15 secret 9 [REDACTED]"),
        (" enable password level 15 7 HASH", " enable password level 15 7 [REDACTED]"),
        (" password 0 \"two words\"", " password 0 [REDACTED]"),
        ("snmp-server community PRIVATE RO ACL", "snmp-server community [REDACTED] RO ACL"),
        ("crypto isakmp key PRIVATE address 192.0.2.1", "crypto isakmp key [REDACTED] address 192.0.2.1"),
        ("neighbor 192.0.2.1 password 7 HASH", "neighbor 192.0.2.1 password 7 [REDACTED]"),
        ("tacacs-server key 7 HASH", "tacacs-server key 7 [REDACTED]"),
        (" key 7 HASH", " key 7 [REDACTED]"),
        (" key 123", " key 123"),
        ("snmp-server user admin group v3 auth sha AUTHVALUE priv aes 128 PRIVVALUE", "snmp-server user admin group v3 auth sha [REDACTED] priv aes 128 [REDACTED]"),
        ("snmp-server host 192.0.2.1 version 2c PRIVATE", "snmp-server host 192.0.2.1 version 2c [REDACTED]"),
        ("username admin password HASH encrypted privilege 15", "username admin password [REDACTED] encrypted privilege 15"),
        (" description password recovery interface", " description password recovery interface"),
        ("no enable password", "no enable password"),
        ("password 7 HASH\r\n", "password 7 [REDACTED]\r\n"),
        ("-----BEGIN PRIVATE KEY-----\nABC\nDEF\n-----END PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----"),
        (" certificate ca 01\n ABC\n DEF\n quit", " certificate ca 01\n[REDACTED]\n quit")
    ]
    for (source,expected) in cases {
        let cleaner = Cleaner()
        let actual = cleaner.clean(source,hostname:false,addresses:false,secrets:true)
        assert(actual == expected, "Credential syntax preservation failed: \(source) => \(actual)")
        assert(cleaner.clean(actual,hostname:false,addresses:false,secrets:true) == actual)
        assert(cleaner.counts == [0,0,0], "Redacting an already cleaned config must be idempotent")
    }
    let diff = DiffInfo("one\ntwo\nthree", "one\nREPLACED\nthree")
    assert(diff.removed == Set([1]) && diff.inserted == Set([1]))
    let multiline = DiffInfo("one\nkey1\nkey2\nthree", "one\nREDACTED\nthree")
    assert(multiline.removed == Set([1,2]) && multiline.inserted == Set([1]))
    let unchanged = DiffInfo("one\ntwo", "one\ntwo")
    assert(unchanged.removed.isEmpty && unchanged.inserted.isEmpty)
    let model = Model()
    model.files = [ConfigFile(url: URL(fileURLWithPath:"/a/router.cfg"), original:"hostname first",outputName:""), ConfigFile(url: URL(fileURLWithPath:"/b/router.cfg"), original:"hostname second",outputName:"")]
    model.refresh()
    assert(model.files.map { $0.outputName } == ["router-clean.cfg", "router-2-clean.cfg"])
    assert(model.totals == [2,0,0])
    model.host = false; model.refresh()
    assert(model.totals == [0,0,0] && model.files[0].cleaned == "hostname first")
    model.selected = model.files[0].id; model.remove(model.files[0].id)
    assert(model.selected == model.files.first?.id && model.files.count == 1)
    let identitySource = "password encryption aes\nip domain name example.internal\nip domain-name example.internal\nsnmp-server location Some street, City\nsnmp-server contact Test Person\n description Building uplink\nbanner motd ^C\nPrivate organization\nOffice address\n^C\ninterface Vlan10\nbanner login #Private message#\nend\n"
    let identityResult = Cleaner().clean(identitySource,hostname:false,addresses:false,secrets:true,identity:true)
    assert(identityResult == "password encryption aes\nip domain name [REDACTED]\nip domain-name [REDACTED]\n description [REDACTED]\ninterface Vlan10\nend\n")
    let snmpCases = [
        ("snmp-server host *10.51.24.9 TEST_COMMUNITY!", "snmp-server host *10.51.24.9 [REDACTED]"),
        ("snmp-server host 192.0.2.1 traps TEST_COMMUNITY udp-port 162", "snmp-server host 192.0.2.1 traps [REDACTED] udp-port 162"),
        ("snmp-server host 192.0.2.1 version 2c TEST_COMMUNITY", "snmp-server host 192.0.2.1 version 2c [REDACTED]"),
        ("snmp-server host 192.0.2.1 version 3 priv myuser", "snmp-server host 192.0.2.1 version 3 priv myuser"),
        (" password encryption aes", " password encryption aes")
    ]
    for (source, expected) in snmpCases {
        assert(Cleaner().clean(source,hostname:false,addresses:false,secrets:true) == expected)
    }
    assert(Cleaner().stripIdentity("banner exec !notice!\r\nend\r\n") == "end\r\n")
    assert(Cleaner().stripIdentity("banner motd ^C\nunterminated private banner") == "")
    let radiusCases: [(String,String)] = [
        (" server-private 192.0.2.93 key 6 TEST_ENCRYPTED_KEY", " server-private 192.0.2.93 key 6 [REDACTED]"),
        ("aaa group server radius SSB_RAD_SERVERS server-private *10.50.20.93 key 6 TEST_ENCRYPTED_KEY", "aaa group server radius SSB_RAD_SERVERS server-private *10.50.20.93 key 6 [REDACTED]"),
        (" server-private 192.0.2.93 auth-port 1812 acct-port 1813 timeout 5 key 7 TEST_KEY", " server-private 192.0.2.93 auth-port 1812 acct-port 1813 timeout 5 key 7 [REDACTED]"),
        (" server-private 2001:db8::1 key TEST_KEY", " server-private 2001:db8::1 key [REDACTED]"),
        (" server-private 192.0.2.93 key 0 \"two words\"", " server-private 192.0.2.93 key 0 [REDACTED]"),
        (" server-private 192.0.2.93 key 6 [REDACTED]", " server-private 192.0.2.93 key 6 [REDACTED]"),
        (" description server-private key troubleshooting", " description server-private key troubleshooting")
    ]
    for (source, expected) in radiusCases {
        let cleaner = Cleaner()
        assert(cleaner.clean(source,hostname:false,addresses:false,secrets:true) == expected)
        assert(cleaner.clean(expected,hostname:false,addresses:false,secrets:true) == expected)
    }
    assert(appVersionLabel == "v1.2.3 (build 6)")
    let suite = "local.cisco.configcleaner.tests." + UUID().uuidString
    let store = UserDefaults(suiteName:suite)!
    let firstLaunch = Model(defaults:store)
    assert(firstLaunch.host && firstLaunch.ip && firstLaunch.secret && firstLaunch.schemeMode)
    firstLaunch.host = false; firstLaunch.ip = false; firstLaunch.secret = false; firstLaunch.schemeMode = false
    firstLaunch.identityOptions = .none
    let nextLaunch = Model(defaults:UserDefaults(suiteName:suite)!)
    assert(!nextLaunch.host && !nextLaunch.ip && !nextLaunch.secret && !nextLaunch.schemeMode)
    assert(nextLaunch.identityOptions == .none)
    nextLaunch.identityOptions.serials = true
    nextLaunch.identityOptions.domains = true
    nextLaunch.ip = true
    let thirdLaunch = Model(defaults:UserDefaults(suiteName:suite)!)
    assert(thirdLaunch.ip && !thirdLaunch.host && !thirdLaunch.secret && !thirdLaunch.schemeMode)
    assert(thirdLaunch.identityOptions.serials && thirdLaunch.identityOptions.domains && !thirdLaunch.identityOptions.banners)
    assert(thirdLaunch.files.isEmpty && thirdLaunch.selected == nil)
    assert(store.dictionaryRepresentation().keys.filter { $0.hasPrefix("cleaning.") }.count == 9)
    let folderRoot = FileManager.default.temporaryDirectory.appendingPathComponent("cisco-folders-" + UUID().uuidString)
    let inputFolder = folderRoot.appendingPathComponent("input")
    let outputFolder = folderRoot.appendingPathComponent("output")
    try! FileManager.default.createDirectory(at:inputFolder,withIntermediateDirectories:true)
    try! FileManager.default.createDirectory(at:outputFolder,withIntermediateDirectories:true)
    assert(thirdLaunch.rememberedFolder(.input) == nil && thirdLaunch.rememberedFolder(.output) == nil)
    thirdLaunch.rememberFolder(inputFolder,for:.input)
    thirdLaunch.rememberFolder(outputFolder,for:.output)
    let fourthLaunch = Model(defaults:UserDefaults(suiteName:suite)!)
    assert(fourthLaunch.rememberedFolder(.input)?.path == inputFolder.path)
    assert(fourthLaunch.rememberedFolder(.output)?.path == outputFolder.path)
    thirdLaunch.rememberFolder(URL(string:"https://example.com")!,for:.input)
    assert(thirdLaunch.rememberedFolder(.input)?.path == inputFolder.path)
    fourthLaunch.files = [ConfigFile(url:inputFolder.appendingPathComponent("reset.cfg"),original:"hostname reset-router\npassword 7 RESET_TEST_KEY\nip address 192.0.2.1 255.255.255.0\n",outputName:"")]
    fourthLaunch.selected = fourthLaunch.files[0].id
    let selectedBeforeReset = fourthLaunch.selected
    fourthLaunch.resetOptions()
    assert(fourthLaunch.host && fourthLaunch.ip && fourthLaunch.schemeMode && fourthLaunch.secret)
    assert(fourthLaunch.identityOptions == IdentityOptions())
    assert(fourthLaunch.files.count == 1 && fourthLaunch.selected == selectedBeforeReset)
    assert(!fourthLaunch.files[0].cleaned.contains("RESET_TEST_KEY"))
    let afterReset = Model(defaults:UserDefaults(suiteName:suite)!)
    assert(afterReset.host && afterReset.ip && afterReset.schemeMode && afterReset.secret)
    assert(afterReset.identityOptions == IdentityOptions())
    assert(afterReset.rememberedFolder(.input)?.path == inputFolder.path)
    assert(afterReset.rememberedFolder(.output)?.path == outputFolder.path)
    print("Reset defaults, persisted options, preview refresh and retained folders checks passed")
    try! FileManager.default.removeItem(at:folderRoot)
    assert(fourthLaunch.rememberedFolder(.input) == nil && fourthLaunch.rememberedFolder(.output) == nil)
    print("Separate input/output folder persistence and missing-folder fallback checks passed")
    store.removePersistentDomain(forName:suite)
    print("Option persistence, false values, nested toggles and clean startup checks passed")
    runCoverageTests()
    runSchemeTests()
    print("All sanitizer, counts, diff, queue and naming checks passed")
} else {
    let app = NSApplication.shared; let delegate = App(); app.setActivationPolicy(.regular); app.delegate = delegate; app.run()
}
