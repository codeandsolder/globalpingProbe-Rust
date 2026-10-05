// Integration tests for private IP detection
// These run against the real system network interfaces

#[test]
fn blocks_all_rfc_private_ranges() {
    use globalping_probe::util::private_ip::is_ip_private;

    let private_cases = [
        "10.0.0.1",
        "10.255.255.255",
        "192.168.0.1",
        "192.168.255.255",
        "172.16.0.1",
        "172.31.255.255",
        "127.0.0.1",
        "127.255.255.255",
        "169.254.0.1",
        "100.64.0.1",
        "::1",
        "fc00::1",
        "fdff::1",
        "fe80::1",
    ];

    for ip in private_cases {
        let parsed: std::net::IpAddr = ip.parse().unwrap();
        assert!(is_ip_private(parsed), "{ip} should be private");
    }
}

#[test]
fn allows_public_ips() {
    use globalping_probe::util::private_ip::is_ip_private;

    let public_cases = ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"];

    for ip in public_cases {
        let parsed: std::net::IpAddr = ip.parse().unwrap();
        assert!(!is_ip_private(parsed), "{ip} should be public");
    }
}
