import Foundation
import Darwin

// A batch-wide XOR permutation preserves address equality and prefix relationships.
// Only bits inside EVERY observed network mask may change, preserving host positions.
// This is structural pseudonymization, not cryptographic anonymization.
final class AddressScheme {
    struct Token {
        let range: NSRange
        let value: String
        let bytes: [UInt8]
        var mask = false
    }
    static let pattern = #"(?i)(?<![\w.:])(?:(?:[0-9a-f]{0,4}:){2,}(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,4})(?![\w.:])"#
    var key4: UInt32 = 0
    var key6 = [UInt8](repeating:0,count:16)
    var has4 = false, has6 = false
    var warning: String {
        var parts: [String] = []
        if has4 && key4 == 0 { parts.append("IPv4 constraints require label replacements") }
        if has6 && key6.allSatisfy({ $0 == 0 }) { parts.append("IPv6 constraints require label replacements") }
        return parts.joined(separator:" · ")
    }
    static func bytes(_ value: String) -> [UInt8]? {
        let family = value.contains(":") ? AF_INET6 : AF_INET
        var buffer = [UInt8](repeating:0,count:family == AF_INET ? 4 : 16)
        let valid = value.withCString { pointer in buffer.withUnsafeMutableBytes { inet_pton(family,pointer,$0.baseAddress!) } }
        return valid == 1 ? buffer : nil
    }
    static func string(_ bytes: [UInt8]) -> String {
        var output = [CChar](repeating:0,count:Int(INET6_ADDRSTRLEN))
        _ = bytes.withUnsafeBytes { inet_ntop(bytes.count == 4 ? AF_INET : AF_INET6,$0.baseAddress!,&output,socklen_t(output.count)) }
        return String(cString:output)
    }
    static func number(_ bytes: [UInt8]) -> UInt32 { bytes.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } }
    static func octets(_ number: UInt32) -> [UInt8] { [24,16,8,0].map { UInt8((number >> $0) & 255) } }
    static func mask(_ prefix: Int) -> UInt32 { prefix == 0 ? 0 : UInt32.max << (32 - prefix) }
    static func contiguous(_ number: UInt32) -> Bool { let inverse = ~number; return inverse & (inverse &+ 1) == 0 }
    static func special(_ b: [UInt8]) -> Bool {
        if b.count == 4 { return b[0] == 0 || b[0] == 127 || b[0] >= 224 || (b[0] == 169 && b[1] == 254) }
        return b[0] == 255 || (b[0] == 254 && b[1] & 0xc0 == 0x80) || b.dropLast().allSatisfy { $0 == 0 } && b.last! <= 1
    }
    static func tokens(_ line: String) -> [Token] {
        let regex = try! NSRegularExpression(pattern:pattern)
        let ns = line as NSString
        var result: [Token] = regex.matches(in:line,range:NSRange(location:0,length:ns.length)).compactMap { match in
            let value = ns.substring(with:match.range)
            guard let data = bytes(value) else { return nil }
            return Token(range:match.range,value:value,bytes:data)
        }
        let lower = line.lowercased()
        let acl = lower.contains("access-list") || lower.trimmingCharacters(in:.whitespaces).hasPrefix("permit ") || lower.trimmingCharacters(in:.whitespaces).hasPrefix("deny ")
        let addressList = lower.contains("name-server") || lower.contains("dns-server")
        for index in result.indices where result[index].bytes.count == 4 {
            let prefix = ns.substring(to:result[index].range.location)
            if prefix.range(of:#"(?i)\b(?:netmask|wildcard-mask|subnet-mask)\h+$"#,options:.regularExpression) != nil { result[index].mask = true; continue }
            guard index > 0, !addressList, !result[index-1].mask, result[index-1].bytes.count == 4 else { continue }
            let gap = NSRange(location:NSMaxRange(result[index-1].range),length:result[index].range.location - NSMaxRange(result[index-1].range))
            guard ns.substring(with:gap).trimmingCharacters(in:.whitespaces).isEmpty else { continue }
            let n = number(result[index].bytes)
            if contiguous(n) || contiguous(~n) || acl { result[index].mask = true }
        }
        return result
    }
    init(_ configs: [String]) {
        var allowed4 = UInt32.max
        var allowed6 = [UInt8](repeating:255,count:16)
        var values4: [[UInt8]] = [], values6: [[UInt8]] = []
        var found4 = false, found6 = false
        for config in configs {
            for line in config.components(separatedBy:.newlines) {
                let tokens = Self.tokens(line)
                let ns = line as NSString
                for token in tokens {
                    if token.mask {
                        let raw = Self.number(token.bytes)
                        // Low-bit masks are wildcard masks; noncontiguous ACL masks are wildcards too.
                        let mask = Self.contiguous(raw) ? raw : ~raw
                        if mask != 0 { allowed4 &= mask; found4 = true }
                        continue
                    }
                    if Self.special(token.bytes) { continue }
                    if token.bytes.count == 4 { values4.append(token.bytes) } else { values6.append(token.bytes) }
                    let suffix = ns.substring(from:NSMaxRange(token.range))
                    if let match = suffix.range(of:#"^/\d{1,3}"#,options:.regularExpression), let prefix = Int(suffix[match].dropFirst()), prefix > 0 {
                        if token.bytes.count == 4 && prefix <= 32 { allowed4 &= Self.mask(prefix); found4 = true }
                        if token.bytes.count == 16 && prefix <= 128 {
                            for i in 0..<16 { let bits = max(0,min(8,prefix - i*8)); allowed6[i] &= bits == 0 ? 0 : UInt8(255 << (8-bits) & 255) }
                            found6 = true
                        }
                    }
                }
            }
        }
        has4 = !values4.isEmpty; has6 = !values6.isEmpty
        // Without a configured prefix, preserve at least /24 and /64 host portions.
        if !found4 { allowed4 &= Self.mask(24) }
        if !found6 { for i in 8..<16 { allowed6[i] = 0 } }
        // Preserve IPv6 address class and the global/ULA prefix's first 16 bits.
        allowed6[0] = 0; allowed6[1] = 0
        var state: UInt64 = 0xA17C9E5D1234ABCD
        func randomByte() -> UInt8 { state ^= state << 13; state ^= state >> 7; state ^= state << 17; return UInt8(state & 255) }
        if let first = values4.first {
            for trial in 0..<512 {
                let candidate = (trial == 0 ? (Self.number(first) ^ 0x0A321400) : Self.number((0..<4).map { _ in randomByte() })) & allowed4
                guard candidate != 0 else { continue }
                if values4.allSatisfy({ !Self.special(Self.octets(Self.number($0) ^ candidate)) }) { key4 = candidate; break }
            }
        }
        if has6 {
            for _ in 0..<512 {
                let candidate = allowed6.map { $0 & randomByte() }
                guard candidate.contains(where: { $0 != 0 }) else { continue }
                if values6.allSatisfy({ value in !Self.special(zip(value,candidate).map { $0 ^ $1 }) }) { key6 = candidate; break }
            }
        }
    }
    func transform(_ text: String, label: (String) -> String) -> (String,Int) {
        var count = 0
        let lines = text.components(separatedBy:"\n").map { line -> String in
            var result = line
            for token in Self.tokens(line).reversed() where !token.mask && !Self.special(token.bytes) {
                let replacement: String
                if token.bytes.count == 4 {
                    replacement = key4 == 0 ? label(Self.string(token.bytes)) : Self.string(Self.octets(Self.number(token.bytes) ^ key4))
                } else {
                    replacement = key6.allSatisfy { $0 == 0 } ? label(Self.string(token.bytes)) : Self.string(zip(token.bytes,key6).map { $0 ^ $1 })
                }
                if let range = Range(token.range,in:result) { result.replaceSubrange(range,with:"*" + replacement); count += 1 }
            }
            return result
        }
        return (lines.joined(separator:"\n"),count)
    }
}
