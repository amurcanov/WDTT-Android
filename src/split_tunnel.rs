use std::net::{IpAddr, Ipv4Addr};

pub fn modify_config_for_split_tunnel(conf: &str, peer_ip: IpAddr) -> String {
    let mut excludes: Vec<(u32, u8)> = Vec::new();

    if let IpAddr::V4(ip) = peer_ip {
        excludes.push((u32::from(ip), 32));
    }

    let cidrs = [
        "95.163.0.0/16",
        "87.240.0.0/16",
        "93.186.224.0/20",
        "185.32.248.0/22",
        "185.29.130.0/24",
        "217.20.144.0/20",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ];

    for cidr in &cidrs {
        if let Some(parsed) = parse_cidr(cidr) {
            excludes.push(parsed);
        }
    }

    let allowed = calc_allowed_ips(&excludes);

    let mut lines = Vec::new();
    for line in conf.lines() {
        if line.trim().starts_with("AllowedIPs") {
            lines.push(format!("AllowedIPs = {}", allowed));
        } else {
            lines.push(line.to_string());
        }
    }
    lines.join("\n")
}

fn parse_cidr(s: &str) -> Option<(u32, u8)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip: Ipv4Addr = parts[0].parse().ok()?;
    let bits: u8 = parts[1].parse().ok()?;
    Some((u32::from(ip), bits))
}

fn calc_allowed_ips(excludes: &[(u32, u8)]) -> String {
    let mut result: Vec<(u32, u8)> = Vec::new();

    fn contains(container: (u32, u8), target: (u32, u8)) -> bool {
        if container.1 > target.1 {
            return false;
        }
        let mask = if container.1 == 0 {
            0u32
        } else {
            0xFFFFFFFFu32 << (32 - container.1)
        };
        (container.0 & mask) == (target.0 & mask)
    }

    fn overlaps(a: (u32, u8), b: (u32, u8)) -> bool {
        let min_bits = std::cmp::min(a.1, b.1);
        let mask = if min_bits == 0 {
            0u32
        } else {
            0xFFFFFFFFu32 << (32 - min_bits)
        };
        (a.0 & mask) == (b.0 & mask)
    }

    fn split_rec(block: (u32, u8), excludes: &[(u32, u8)], result: &mut Vec<(u32, u8)>) {
        for ex in excludes {
            if contains(*ex, block) {
                return;
            }
        }
        if !excludes.iter().any(|ex| overlaps(block, *ex)) {
            result.push(block);
            return;
        }
        if block.1 >= 32 {
            return;
        }
        let next = block.1 + 1;
        let bit = 1u32 << (32 - next);
        split_rec((block.0, next), excludes, result);
        split_rec((block.0 | bit, next), excludes, result);
    }

    split_rec((0, 0), excludes, &mut result);

    result
        .iter()
        .map(|(ip, bits)| {
            let addr = Ipv4Addr::from(*ip);
            format!("{}/{}", addr, bits)
        })
        .collect::<Vec<_>>()
        .join(", ")
}