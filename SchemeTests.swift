import Foundation

func runSchemeTests() {
    let labels = Cleaner()
    let labelOutput = labels.clean("time 12:34:56\nneighbor ::ffff:192.0.2.1\nneighbor 0:0:0:0:0:ffff:c000:201",hostname:false,addresses:true,secrets:false,marked:true)
    let labelLines = labelOutput.components(separatedBy:"\n")
    assert(labelLines[0] == "time 12:34:56" && labelLines[1] == labelLines[2])
    assert(labelLines[1].hasPrefix("neighbor *IP_") && labels.counts[1] == 2)
    let highWildcard = AddressScheme(["access-list 101 permit ip 10.1.2.3 255.0.0.0 any"])
    assert(highWildcard.key4 != 0 && highWildcard.key4 & 0xff000000 == 0)
    let explicitWildcard = AddressScheme(["network 10.1.2.3 wildcard-mask 255.0.0.0"])
    assert(explicitWildcard.key4 != 0 && explicitWildcard.key4 & 0xff000000 == 0)
    let config = """
    interface Vlan10
     ip address 192.168.10.1 255.255.255.0
    ip route 192.168.10.0 255.255.255.0 192.168.20.1
    ip route 0.0.0.0 0.0.0.0 192.168.10.254
    access-list 100 permit ip 192.168.10.0 0.0.0.255 192.168.20.0 0.0.0.255
    network 192.168.10.0/24
    ip name-server 192.168.10.2 192.168.20.2
    """
    let scheme = AddressScheme([config])
    let c = Cleaner()
    let cleaned = c.clean(config,hostname:false,addresses:true,secrets:true,scheme:scheme,marked:true)
    assert(cleaned.contains("ip address *10.50.20.1 255.255.255.0"))
    assert(cleaned.contains("ip route 0.0.0.0 0.0.0.0 *10.50.20.254"))
    assert(cleaned.contains("network *10.50.20.0/24"))
    assert(cleaned.contains("*10.50.20.0 0.0.0.255"))
    assert(!cleaned.contains("*255.255.255.0") && !cleaned.contains("*0.0.0.255"))
    let restored = cleaned.replacingOccurrences(of:"*",with:"")
    assert(AddressScheme.tokens(restored.components(separatedBy:"\n")[1]).count == 2)
    assert(scheme.key4 & 255 == 0)
    let mask = AddressScheme.mask(24)
    let a = AddressScheme.number(AddressScheme.bytes("192.168.10.1")!)
    let b = AddressScheme.number(AddressScheme.bytes("192.168.10.0")!)
    assert(((a ^ scheme.key4) & mask) == (b ^ scheme.key4))
    // Broader routes constrain the mapping so host positions survive every configured subnet.
    let broad = AddressScheme(["ip address 10.12.1.5 255.255.255.0\nip route 10.0.0.0 255.0.0.0 10.12.1.1"])
    assert(broad.key4 != 0 && broad.key4 & 0x00ffffff == 0)
    // All common prefix sizes preserve network and host relationships.
    for prefix in 8...32 {
        let m = AddressScheme.mask(prefix)
        let address: UInt32 = 0xC0A80A19
        let network = address & m
        let sample = "ip address \(AddressScheme.string(AddressScheme.octets(address))) \(AddressScheme.string(AddressScheme.octets(m)))\nnetwork \(AddressScheme.string(AddressScheme.octets(network)))/\(prefix)"
        let mapped = AddressScheme([sample])
        assert(mapped.key4 != 0)
        assert(mapped.key4 & ~m == 0)
        assert(((address ^ mapped.key4) & m) == (network ^ mapped.key4))
        assert(((address ^ mapped.key4) & ~m) == (address & ~m))
    }
    let ipv6 = "ipv6 address 2001:db8:10::1/64\nipv6 route 2001:db8:10::/64 2001:db8:20::2\nipv6 route ::/0 2001:db8:10::2\nneighbor 2001:0db8:0010:0000:0000:0000:0000:0001\nipv6 address fe80::1 link-local"
    let v6 = AddressScheme([ipv6])
    let transformed = c.clean(ipv6,hostname:false,addresses:true,secrets:true,scheme:v6)
    assert(!transformed.contains("2001:db8:10::1"))
    assert(transformed.contains("ipv6 route ::/0") && transformed.contains("fe80::1 link-local"))
    assert(v6.key6.dropFirst(8).allSatisfy { $0 == 0 })
    let mapped6 = AddressScheme.string(zip(AddressScheme.bytes("2001:db8:10::1")!,v6.key6).map { $0 ^ $1 })
    assert(transformed.contains("ipv6 address *\(mapped6)/64") && transformed.contains("neighbor *\(mapped6)"))
    // Special protocol addresses stay intact; actual masks stay intact while .0 host addresses map.
    let special = "ip route 0.0.0.0 0.0.0.0 192.168.10.1\nntp server 127.0.0.1\nmulticast 224.0.0.5\nserver 255.255.255.255\nneighbor 192.168.10.0"
    let specials = c.clean(special,hostname:false,addresses:true,secrets:true,scheme:AddressScheme([special]))
    assert(specials.contains("127.0.0.1") && specials.contains("224.0.0.5") && specials.contains("255.255.255.255"))
    assert(!specials.contains("neighbor 192.168.10.0"))
    // Numeric-only label mode remains available; original mode is unchanged.
    assert(c.clean(config,hostname:false,addresses:false,secrets:false,scheme:scheme) == config)
    let label = c.clean("ip address 192.168.1.1 255.255.255.0",hostname:false,addresses:true,secrets:false,marked:true)
    assert(label.contains("*IP_"))
    let model = Model()
    model.files = [ConfigFile(url:URL(fileURLWithPath:"/tmp/router.cfg"),original:config,outputName:"")]
    model.refresh()
    let exported = model.exportText(model.files[0])
    assert(exported.contains("ANONYMIZED REVIEW COPY") && exported.contains("*10.50.20.1 255.255.255.0"))
    assert(exported.contains("other commands may still execute"))
    // When a batch cannot be safely permuted within its constraints, use explicit labels.
    let constrained = AddressScheme(["ipv6 address 2001::1/16"])
    assert(!constrained.warning.isEmpty)
    assert(c.clean("ipv6 address 2001::1/16",hostname:false,addresses:true,secrets:false,scheme:constrained).contains("*IP_"))
    print("Address mapping, prefix/host preservation, masks, markers and export legend checks passed")
}
