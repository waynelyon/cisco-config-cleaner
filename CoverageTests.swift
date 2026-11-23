import Foundation

func runCoverageTests() {
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
        assert(c.counts == [0,0,0])
        assert(c.clean(source,hostname:false,addresses:false,secrets:false) == source)
    }
    let intact = ["password encryption aes", "key chain ROUTING_KEYS", " key 42", "standby 1 authentication md5 key-chain HSRP_KEYS", "ip ospf authentication key-chain OSPF_KEYS", "password strength minimum 12", "crypto isakmp client configuration group VPN_USERS", "no enable password", "interface Serial0/0/0"]
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
    print("Extended Cisco secret formats and independent metadata/serial options passed")
}
