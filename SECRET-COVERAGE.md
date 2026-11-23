# Secret audit — version 1.2.0, build 3

The audit found missing or incorrectly parsed NTP key IDs/algorithms, IKE local/remote and peer-address forms, OSPF MD5 keys (including different type-marker positions), HSRP plaintext authentication, legacy RADIUS/TACACS per-host keys, ASA passwd/LDAP values, smart-license tokens and master password-encryption keys. Rules now replace values with [REDACTED] while retaining command prefixes, key IDs, algorithms, type markers and trailing options in the tested formats.

Existing coverage was regression-checked for local/enable passwords and hashes, RADIUS private-server keys, SNMP communities and v3 auth/privacy, BGP passwords, key-chain key strings, PPP PAP/CHAP passwords, WPA PSKs, credential-bearing URLs and PEM/certificate payloads. These are known-format rules, not a complete Cisco grammar or an exhaustive guarantee across every release.

Non-secret controls explicitly preserved include password encryption aes, key-chain names, numeric key IDs, routing key-chain references, password-strength settings and Serial interface names. Banner removal remains for IOS delimiter-style blocks; arbitrary banner variants and unknown structured configuration exports require review.

## Independent options

All five additional options default on and can be disabled separately: banner removal, location/contact removal, domain-name redaction, description redaction, and serial-number redaction. Serial detection uses explicit license UDI, SN:, serial-number, system/chassis serial number and processor board ID fields. It also redacts repeated instances of discovered serials in that file, without changing product IDs or Serial interface names. Unlabeled serial values cannot reliably be identified by this rule.

The metadata options do not affect the three hostname/IP/credential counters. Test cases verify option independence and byte-for-byte command preservation, including negative cases and repeated cleaning.

## Cisco references reviewed

- [NTP commands](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/bsm/command/bsm-cr-book/m_bsm-cr-n1.html)
- [NTP algorithms in IOS XE](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/syst-mgmt/b-system-management/m_bsm-time-calendar-set.html)
- [Pre-shared key local/remote commands](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/m1/sec-m1-cr-book/sec-cr-p2.html)
- [Peer-address pre-shared key example](https://www.cisco.com/c/en/us/support/docs/routers/sd-wan/224128-improve-throughput-on-catalyst-8000v.html)
- [OSPF command syntax](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/iproute_ospf/command/iro-cr-book/ospf-i1.html)
- [NX-OS OSPF key types](https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus5500/sw/command/reference/unicast/n5500-ucast-cr/n5500-ospf_cmds_i.pdf)
- [HSRP key strings](https://www.cisco.com/c/en/us/td/docs/ios/ipapp/command/reference/iap_s5.pdf)
- [PPP PAP command](https://www.cisco.com/E-Learning/bulk/public/tac/cim/cib/using_cisco_ios_software/cmdrefs/ppp_pap_sent-username.htm)
- [License UDI serial format](https://www.cisco.com/c/en/us/td/docs/ios/csa/configuration/guide/csa_commands.html)
