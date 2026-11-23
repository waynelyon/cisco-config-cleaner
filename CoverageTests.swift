import Foundation

func expectSecret(_ source: String, _ expected: String) {
    let cleaner = Cleaner()
    assert(cleaner.clean(source,hostname:false,addresses:false,secrets:true) == expected, "Credential regression: " + source)
    assert(cleaner.clean(expected,hostname:false,addresses:false,secrets:true) == expected, "Repeat cleaning changed commands")
}

func runCoverageTests() {
    expectSecret("mka pre-shared-key key-chain SW1-SW2-MACSEC", "mka pre-shared-key key-chain SW1-SW2-MACSEC")
    expectSecret("key chain SW1-SW2-MACSEC macsec\n key 100\n  key-string DEMO_KEY", "key chain SW1-SW2-MACSEC macsec\n key 100\n  key-string [REDACTED]")
    let extra = Model.extraIdentityRedaction("username alice secret 9 [REDACTED]\nmac address-table static aabb.ccdd.eeff\ncircuit-id CUSTOMER-123")
    assert(!extra.contains("alice") && !extra.contains("aabb.ccdd.eeff") && !extra.contains("CUSTOMER-123"))
    assert(Model.extraIdentityRedaction("aa:bb:cc:dd:ee:ff AA-BB-CC-DD-EE-FF") == "[MAC_REDACTED] [MAC_REDACTED]")
    assert(Model.extraIdentityRedaction("username alice secret 9 [REDACTED]",usernames:false) == "username alice secret 9 [REDACTED]")
    assert(Model.possibleSecretLines("api_key TEST_TOKEN\npassword [REDACTED]") == 1)
    let privacy = Model()
    privacy.files = [ConfigFile(url:URL(fileURLWithPath:"/tmp/customer.cfg"),original:"username alice secret 9 DEMO\nmac address-table static aabb.ccdd.eeff\ncircuit-id CUSTOMER-123",outputName:"")]
    privacy.aiSafePreset()
    assert(privacy.files[0].outputName == "device-1-clean.cfg")
    assert(!privacy.files[0].cleaned.contains("alice") && !privacy.files[0].cleaned.contains("CUSTOMER-123") && !privacy.files[0].cleaned.contains("DEMO"))
    let exportFolder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try! FileManager.default.createDirectory(at:exportFolder,withIntermediateDirectories:true)
    defer { try? FileManager.default.removeItem(at:exportFolder) }
    let originalURL = exportFolder.appendingPathComponent("router.cfg")
    try! Data("password 0 DEMO".utf8).write(to:originalURL)
    let exportModel = Model(); exportModel.add([originalURL])
    let firstExport = try! exportModel.export(to:exportFolder)
    let secondExport = try! exportModel.export(to:exportFolder)
    assert(firstExport[0].lastPathComponent == "router-clean.cfg" && secondExport[0].lastPathComponent == "router-2-clean.cfg")
    assert((try! String(contentsOf:originalURL,encoding:.utf8)) == "password 0 DEMO")
    assert(!(try! String(contentsOf:firstExport[0],encoding:.utf8)).contains("DEMO"))
    exportModel.anonymousNames = true
    let anonymous = try! exportModel.export(to:exportFolder)
    assert(anonymous[0].lastPathComponent == "device-1-clean.cfg")
    exportModel.anonymousNames = false
    exportModel.files = [ConfigFile(url:originalURL,cleaned:"safe",outputName:"partial-clean.cfg"),ConfigFile(url:originalURL,cleaned:"safe",outputName:String(repeating:"x",count:300))]
    assert((try? exportModel.export(to:exportFolder)) == nil)
    assert(exportModel.status == "Saved 1 files before an error")
    assert(FileManager.default.fileExists(atPath:exportFolder.appendingPathComponent("partial-clean.cfg").path))
    let longPreview = DiffInfo(String(repeating:"é",count:200_001),"")
    assert(longPreview.truncated && longPreview.original[0].count == 200_000)
    let manyLines = DiffInfo(String(repeating:"line\n",count:10_000),"")
    assert(manyLines.truncated && manyLines.original.count == 2000)
    assert(DiffInfo("one\rtwo", "one\r\ntwo").original == ["one","two"])
    let background = Model(backgroundCleaning:true)
    background.files = [ConfigFile(url:URL(fileURLWithPath:"/tmp/background.cfg"),original:"hostname edge\npassword 0 DEMO",outputName:"")]
    background.files[0].cleaned = "password 0 DEMO"
    background.refresh()
    assert(background.isProcessing && background.files[0].cleaned.isEmpty)
    background.host = false
    let deadline = Date().addingTimeInterval(10)
    while background.isProcessing && Date() < deadline { _ = RunLoop.current.run(mode:.default,before:Date().addingTimeInterval(0.01)) }
    assert(!background.isProcessing && background.files[0].cleaned == "hostname edge\npassword 0 [REDACTED]")
    background.resetOptions()
    background.files = []; background.refresh()
    assert(!background.isProcessing && background.files.isEmpty)
    let readURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at:readURL) }
    try! Data("test".utf8).write(to:readURL)
    assert((try? Model.readConfiguration(readURL,limit:4)) == "test")
    assert((try? Model.readConfiguration(readURL,limit:3)) == nil)
    let limited = Model(maximumBatchBytes:3,maximumFiles:1)
    limited.add([readURL])
    assert(limited.ready.isEmpty && limited.files[0].original.isEmpty && limited.files[0].error!.contains("Batch"))
    limited.add([readURL.appendingPathExtension("other")])
    assert(limited.files.count == 1 && limited.status.contains("Queue limit"))
    try! Data([0,65]).write(to:readURL)
    assert((try? Model.readConfiguration(readURL,limit:4)) == nil)
    let neighbors = Array(repeating:"neighbor password password 7 DEMO",count:500).joined(separator:"\n")
    let many = Cleaner()
    let manyOutput = many.clean(neighbors,hostname:false,addresses:false,secrets:true)
    assert(!manyOutput.contains("DEMO") && many.counts[2] == 500)
    assert(manyOutput.components(separatedBy:"\n").allSatisfy { $0 == "neighbor password password 7 [REDACTED]" })
    expectSecret("username vrf password 0 DEMO_HASH", "username vrf password 0 [REDACTED]")
    assert(Cleaner().clean("hostname edge\nntp server EDGE\nlogging host Edge",hostname:true,addresses:false,secrets:true) == "hostname DEVICE_1\nntp server DEVICE_1\nlogging host DEVICE_1")
    let bom = "\u{FEFF}hostname edge\rpassword 0 DEMO"
    assert(Cleaner().clean(bom,hostname:true,addresses:false,secrets:true) == "hostname DEVICE_1\rpassword 0 [REDACTED]")
    assert(Cleaner().clean(bom,hostname:false,addresses:false,secrets:false) == bom)
    let mixedUnchanged = "! comment\rpassword 0 DEMO\nend"
    assert(Cleaner().clean(mixedUnchanged,hostname:false,addresses:false,secrets:false) == mixedUnchanged)
    let copiedLines = ["hostname DEVICE_1", " description café"]
    assert(ConfigurationTextView.copiedText(copiedLines,selection:NSRange(location:0,length:1000)) == copiedLines.joined(separator:"\n") + "\n")
    assert(ConfigurationTextView.copiedText(copiedLines,selection:NSRange(location:0,length:4)).isEmpty)
    assert(ConfigurationTextView.copiedText(copiedLines,selection:NSRange(location:8,length:8)) == "hostname")
    var serialOptions = IdentityOptions.none; serialOptions.serials = true
    let serialOutput = Cleaner().clean("serial-number password\npassword encryption aes\n! device password",hostname:false,addresses:false,secrets:true,identityOptions:serialOptions)
    assert(serialOutput == "serial-number [REDACTED]\npassword encryption aes\n! device [REDACTED]")
    expectSecret("key\tchain KEYS\n key 42\n  key-string 0 DEMO", "key\tchain KEYS\n key 42\n  key-string 0 [REDACTED]")
    expectSecret("key  chain KEYS\n key 42", "key  chain KEYS\n key 42")
    expectSecret("snmp-server community password RO", "snmp-server community [REDACTED] RO")
    expectSecret("snmp-server host 192.0.2.1 password udp-port 162", "snmp-server host 192.0.2.1 [REDACTED] udp-port 162")
    expectSecret("snmp-server host 192.0.2.1 version 3 priv password", "snmp-server host 192.0.2.1 version 3 priv password")
    expectSecret("! comment\rpassword 0 DEMO_SECRET\r", "! comment\rpassword 0 [REDACTED]\r")
    expectSecret("! comment\rpassword 0 DEMO_SECRET\nend", "! comment\npassword 0 [REDACTED]\nend")
    expectSecret("-----BEGIN PRIVATE KEY-----\nDEMO_PRIVATE\nMORE", "-----BEGIN PRIVATE KEY-----\n[REDACTED]")
    expectSecret(" certificate ca 01\nDEMO_CERT", " certificate ca 01\n[REDACTED]")
    expectSecret(#"password 0 "alpha\"bravo""#, "password 0 [REDACTED]")
    expectSecret(#"password 0 "unterminated two words"#, "password 0 [REDACTED]")
    expectSecret(#"password 0 'alpha\'bravo'"#, "password 0 [REDACTED]")
    expectSecret(#"password 0 "alpha beta\"#, "password 0 [REDACTED]")
    expectSecret("password strengthSecret", "password [REDACTED]")
    expectSecret("password policySecret", "password [REDACTED]")
    expectSecret("password strength", "password [REDACTED]")
    expectSecret("username password secret 9 DEMO_HASH", "username password secret 9 [REDACTED]")
    expectSecret("username secret password 0 DEMO_SECRET", "username secret password 0 [REDACTED]")
    let cases: [(String,String)] = [
        ("ip ospf message-digest-key 1 7 md5 DEMO_KEY", "ip ospf message-digest-key 1 7 md5 [REDACTED]"),
        ("ip ospf message-digest-key 1 md5 3 DEMO_KEY", "ip ospf message-digest-key 1 md5 3 [REDACTED]"),
        ("ntp authentication-key 42 md5 DEMO_KEY 7", "ntp authentication-key 42 md5 [REDACTED] 7"),
        ("ntp authentication-key 12 hmac-sha2-256 DEMO_KEY", "ntp authentication-key 12 hmac-sha2-256 [REDACTED]"),
        (" authentication-key 42 md5 clear DEMO_KEY", " authentication-key 42 md5 clear [REDACTED]"),
        (" pre-shared-key local 6 DEMO_KEY", " pre-shared-key local 6 [REDACTED]"),
        (" pre-shared-key remote 0 DEMO_KEY", " pre-shared-key remote 0 [REDACTED]"),
        (" pre-shared-key address 192.0.2.1 key DEMO_KEY", " pre-shared-key address 192.0.2.1 key [REDACTED]"),
        (" pre-shared-key address 192.0.2.0 255.255.255.0 key 6 DEMO_KEY", " pre-shared-key address 192.0.2.0 255.255.255.0 key 6 [REDACTED]"),
        (" ip ospf message-digest-key 1 md5 7 DEMO_KEY", " ip ospf message-digest-key 1 md5 7 [REDACTED]"),
        (" ip ospf authentication-key 7 DEMO_KEY", " ip ospf authentication-key 7 [REDACTED]"),
        (" standby 1 authentication md5 key-string 7 DEMO_KEY timeout 30", " standby 1 authentication md5 key-string 7 [REDACTED] timeout 30"),
        (" standby 1 authentication text DEMO_KEY", " standby 1 authentication text [REDACTED]"),
        (" standby 1 authentication DEMO_KEY", " standby 1 authentication [REDACTED]"),
        ("radius-server host 192.0.2.1 auth-port 1812 key 7 DEMO_KEY", "radius-server host 192.0.2.1 auth-port 1812 key 7 [REDACTED]"),
        ("tacacs-server host 192.0.2.1 key DEMO_KEY", "tacacs-server host 192.0.2.1 key [REDACTED]"),
        (" ppp pap sent-username provider password 7 DEMO_KEY", " ppp pap sent-username provider password 7 [REDACTED]"),
        (" ppp chap password 0 DEMO_KEY", " ppp chap password 0 [REDACTED]"),
        ("ldap-login-password DEMO_KEY", "ldap-login-password [REDACTED]"),
        ("passwd DEMO_KEY encrypted", "passwd [REDACTED] encrypted"),
        ("license smart register idtoken DEMO_KEY force", "license smart register idtoken [REDACTED] force"),
        ("key config-key password-encrypt DEMO_KEY", "key config-key password-encrypt [REDACTED]"),
        ("wpa-psk ascii 7 DEMO_KEY", "wpa-psk ascii 7 [REDACTED]"),
        ("username admin algorithm-type scrypt secret DEMO_KEY", "username admin algorithm-type scrypt secret [REDACTED]")
    ]
    for (source,expected) in cases {
        let c = Cleaner()
        let actual = c.clean(source,hostname:false,addresses:false,secrets:true)
        assert(actual == expected, "Incorrect credential handling: \(source) => \(actual)")
        assert(c.clean(actual,hostname:false,addresses:false,secrets:true) == actual)
        assert(c.counts == [0,0,0,0])
        assert(c.clean(source,hostname:false,addresses:false,secrets:false) == source)
    }
    let intact = ["password encryption aes", "key chain ROUTING_KEYS", "standby 1 authentication md5 key-chain HSRP_KEYS", "ip ospf authentication key-chain OSPF_KEYS", "password strength minimum 12", "crypto isakmp client configuration group VPN_USERS", "no enable password", "interface Serial0/0/0"]
    for line in intact { assert(Cleaner().clean(line,hostname:false,addresses:false,secrets:true) == line, "Changed non-secret command: \(line)") }
    let sample = "banner motd #private banner#\nsnmp-server location Test office\nip domain name example.test\n description Test uplink\nlicense udi pid C8000 sn FOC12345678\ninterface Serial0/0/0\n"
    let cleaner = Cleaner()
    assert(cleaner.stripIdentity(sample,options:.none) == sample)
    let fields: [(WritableKeyPath<IdentityOptions,Bool>,String,String)] = [
        (\IdentityOptions.banners,"private banner","snmp-server location Test office"),
        (\IdentityOptions.location,"Test office","ip domain name example.test"),
        (\IdentityOptions.domains,"example.test","description Test uplink"),
        (\IdentityOptions.descriptions,"Test uplink","snmp-server location Test office"),
        (\IdentityOptions.serials,"FOC12345678","interface Serial0/0/0")
    ]
    for (key,removed,retained) in fields {
        var options = IdentityOptions.none; options[keyPath:key] = true
        let output = cleaner.stripIdentity(sample,options:options)
        assert(!output.contains(removed) && output.contains(retained))
        assert(cleaner.stripIdentity(output,options:options) == output)
    }
    let inventory = "PID: C9300, VID: V01, SN: FOC12345678\nSystem serial number : FOC87654321\nProcessor board ID FOC11112222\nserial-number FOC33334444\ninterface Serial0/0/0\n"
    let output = cleaner.stripIdentity(inventory,options:IdentityOptions(banners:false,location:false,domains:false,descriptions:false,serials:true))
    for serial in ["FOC12345678","FOC87654321","FOC11112222","FOC33334444"] { assert(!output.contains(serial)) }
    assert(output.contains("PID: C9300") && output.contains("interface Serial0/0/0"))
    // Exercise the actual model path: every option disabled must preserve identity metadata.
    let model = Model(); model.host = false; model.ip = false; model.secret = false; model.identityOptions = .none
    model.files = [ConfigFile(url:URL(fileURLWithPath:"/tmp/options.cfg"),original:sample,outputName:"")]
    model.refresh(); assert(model.files[0].cleaned == sample)
    model.identityOptions = IdentityOptions(); model.refresh()
    assert(!model.files[0].cleaned.contains("FOC12345678") && !model.files[0].cleaned.contains("private banner"))
    // Exercise the export boundary with names that used to rewrite credential grammar.
    for keyword in ["password", "secret", "key", "encryption"] {
        let model = Model()
        model.files = [
            ConfigFile(url:URL(fileURLWithPath:"/tmp/name.cfg"),original:"hostname \(keyword)\nusername admin password 0 SAME_FILE_SECRET\npassword encryption aes",outputName:""),
            ConfigFile(url:URL(fileURLWithPath:"/tmp/credentials.cfg"),original:"username admin secret 9 CROSS_FILE_SECRET\nlogging host \(keyword)",outputName:"")
        ]
        model.refresh()
        assert(model.files[0].cleaned.contains("username admin password 0 [REDACTED]"))
        assert(model.files[0].cleaned.contains("password encryption aes"))
        assert(model.files[1].cleaned.contains("username admin secret 9 [REDACTED]"))
        assert(model.files[1].cleaned.contains("logging host DEVICE_1"))
        for file in model.files { assert(!model.exportText(file).contains("FILE_SECRET")) }
        model.secret = false; model.refresh()
        assert(model.files[0].cleaned.contains("username admin password 0 SAME_FILE_SECRET"))
    }
    let aliases = Cleaner()
    aliases.discoverHosts("hostname long-router-name\nhostname DEVICE_1")
    assert(aliases.clean("hostname long-router-name\nhostname DEVICE_1",hostname:true,addresses:false,secrets:false) == "hostname DEVICE_1\nhostname DEVICE_2")
    for replaceHost in [true, false] {
        let name = replaceHost ? "DEVICE_1" : "password"
        let actual = Cleaner().clean("hostname password\nlogging host password transport tcp port 514\nntp server password prefer\nneighbor password password 7 DEMO_SECRET",hostname:replaceHost,addresses:false,secrets:true)
        assert(actual == "hostname \(name)\nlogging host \(name) transport tcp port 514\nntp server \(name) prefer\nneighbor \(name) password 7 [REDACTED]")
    }
    let vrfHosts = Cleaner().clean("hostname edge\nntp server vrf Mgmt edge\nsnmp-server host vrf Mgmt edge version 2c COMMUNITY",hostname:true,addresses:false,secrets:true)
    assert(vrfHosts == "hostname DEVICE_1\nntp server vrf Mgmt DEVICE_1\nsnmp-server host vrf Mgmt DEVICE_1 version 2c [REDACTED]")
    let bannerCommands = Cleaner().clean("banner motd #password 0 payload#\nhostname edge",hostname:true,addresses:false,secrets:true,identityOptions:IdentityOptions())
    assert(bannerCommands == "hostname DEVICE_1")
    let serverKeys = "radius server R1\n address ipv4 192.0.2.1\n key 123456789\n!\ntacacs server T1\n key 987654321\n!\nkey chain ROUTING\n key 42\n  key-string 0 ROUTING_SECRET\n!\nradius server R2\n key 0 123456789\n"
    let keys = Cleaner().clean(serverKeys,hostname:false,addresses:false,secrets:true)
    assert(!keys.contains("123456789") && !keys.contains("987654321") && !keys.contains("ROUTING_SECRET"))
    assert(keys.contains("key chain ROUTING\n key 42\n  key-string 0 [REDACTED]"))
    assert(keys.contains(" key 0 [REDACTED]"))
    assert(Cleaner().clean(serverKeys.replacingOccurrences(of:"\n",with:"\r\n"),hostname:false,addresses:false,secrets:true) == keys.replacingOccurrences(of:"\n",with:"\r\n"))
    assert(Cleaner().clean(keys,hostname:false,addresses:false,secrets:true) == keys)
    let noSeparator = "key chain ROUTING\n key 42\nradius server R1\n key 123456789"
    assert(Cleaner().clean(noSeparator,hostname:false,addresses:false,secrets:true).hasSuffix(" key [REDACTED]"))
    let metadata = Model(); metadata.host = false; metadata.ip = false; metadata.secret = false
    metadata.files = [ConfigFile(url:URL(fileURLWithPath:"/tmp/metadata.cfg"),original:sample,outputName:"")]
    metadata.refresh()
    assert(metadata.files[0].counts == [0,0,0,5] && metadata.files[0].total == 5 && metadata.totals[3] == 5)
    let secondPass = Cleaner()
    _ = secondPass.clean(metadata.files[0].cleaned,hostname:false,addresses:false,secrets:false,identityOptions:IdentityOptions())
    assert(secondPass.counts == [0,0,0,0])
    let multilineBanner = Cleaner()
    _ = multilineBanner.clean("banner motd ^C\nprivate\n^C",hostname:false,addresses:false,secrets:false,identityOptions:IdentityOptions())
    assert(multilineBanner.counts[3] == 3)
    print("Security regressions: cross-file keyword hostnames, alias collisions, numeric server keys, key-chain IDs, and metadata totals passed")
    print("Extended Cisco secret formats and independent metadata/serial options passed")
}
