//! STUN/TURN протокол — полная реализация на чистом Rust.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

pub const STUN_MAGIC: u32 = 0x2112A442;
pub const HEADER_SIZE: usize = 20;

// Message types
pub const ALLOCATE_REQUEST: u16 = 0x0003;
pub const ALLOCATE_SUCCESS: u16 = 0x0103;
pub const ALLOCATE_ERROR: u16 = 0x0113;
pub const REFRESH_REQUEST: u16 = 0x0004;
pub const CREATE_PERM_REQUEST: u16 = 0x0008;
pub const CREATE_PERM_SUCCESS: u16 = 0x0108;
pub const CHANNEL_BIND_REQUEST: u16 = 0x0009;
pub const CHANNEL_BIND_SUCCESS: u16 = 0x0109;
pub const SEND_INDICATION: u16 = 0x0016;
pub const DATA_INDICATION: u16 = 0x0017;
pub const BINDING_REQUEST: u16 = 0x0001;

// Attribute types
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MSG_INTEGRITY: u16 = 0x0008;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_CHANNEL_NUMBER: u16 = 0x000C;
pub const ATTR_LIFETIME: u16 = 0x000D;
pub const ATTR_XOR_PEER_ADDR: u16 = 0x0012;
pub const ATTR_DATA: u16 = 0x0013;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_XOR_RELAYED_ADDR: u16 = 0x0016;
pub const ATTR_REQ_TRANSPORT: u16 = 0x0019;
pub const ATTR_XOR_MAPPED_ADDR: u16 = 0x0020;

#[derive(Debug)]
pub struct StunMessage {
    pub msg_type: u16,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<(u16, Vec<u8>)>,
}

impl StunMessage {
    pub fn get_attr(&self, attr_type: u16) -> Option<&[u8]> {
        self.attributes
            .iter()
            .find(|(t, _)| *t == attr_type)
            .map(|(_, v)| v.as_slice())
    }

    pub fn get_string_attr(&self, attr_type: u16) -> Option<String> {
        self.get_attr(attr_type)
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }
}

pub fn gen_tid() -> [u8; 12] {
    let mut tid = [0u8; 12];
    rand::Rng::fill(&mut rand::thread_rng(), &mut tid);
    tid
}

fn stun_header(msg_type: u16, length: u16, tid: &[u8; 12]) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_SIZE);
    h.extend_from_slice(&msg_type.to_be_bytes());
    h.extend_from_slice(&length.to_be_bytes());
    h.extend_from_slice(&STUN_MAGIC.to_be_bytes());
    h.extend_from_slice(tid);
    h
}

fn stun_attr(attr_type: u16, value: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(4 + value.len() + 3);
    a.extend_from_slice(&attr_type.to_be_bytes());
    a.extend_from_slice(&(value.len() as u16).to_be_bytes());
    a.extend_from_slice(value);
    let pad = (4 - (value.len() % 4)) % 4;
    a.extend(std::iter::repeat(0u8).take(pad));
    a
}

fn long_term_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    let input = format!("{}:{}:{}", username, realm, password);
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    hasher.finalize().to_vec()
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result.into_bytes());
    out
}

fn append_integrity(msg: &mut Vec<u8>, username: &str, realm: &str, password: &str) {
    let key = long_term_key(username, realm, password);

    // Установить длину в заголовке как будто integrity уже есть (24 байта)
    let final_attrs_len = (msg.len() - HEADER_SIZE + 24) as u16;
    msg[2..4].copy_from_slice(&final_attrs_len.to_be_bytes());

    let integrity = hmac_sha1(&key, msg);
    let integrity_attr = stun_attr(ATTR_MSG_INTEGRITY, &integrity);
    msg.extend_from_slice(&integrity_attr);

    // Обновить финальную длину
    let total_attrs = (msg.len() - HEADER_SIZE) as u16;
    msg[2..4].copy_from_slice(&total_attrs.to_be_bytes());
}

fn xor_peer_addr_value(peer: SocketAddr) -> Vec<u8> {
    let mut v = Vec::with_capacity(8);
    v.push(0); // reserved
    v.push(0x01); // IPv4
    let xor_port = peer.port() ^ ((STUN_MAGIC >> 16) as u16);
    v.extend_from_slice(&xor_port.to_be_bytes());
    match peer.ip() {
        IpAddr::V4(ip) => {
            let xor_ip = u32::from(ip) ^ STUN_MAGIC;
            v.extend_from_slice(&xor_ip.to_be_bytes());
        }
        _ => panic!("IPv6 not supported"),
    }
    v
}

// ================ Builders ================

pub fn build_allocate_unauth() -> (Vec<u8>, [u8; 12]) {
    let tid = gen_tid();
    let transport = stun_attr(ATTR_REQ_TRANSPORT, &[17, 0, 0, 0]); // UDP
    let len = transport.len() as u16;
    let mut msg = stun_header(ALLOCATE_REQUEST, len, &tid);
    msg.extend_from_slice(&transport);
    (msg, tid)
}

pub fn build_allocate_auth(
    username: &str,
    password: &str,
    realm: &str,
    nonce: &str,
) -> (Vec<u8>, [u8; 12]) {
    let tid = gen_tid();

    let transport = stun_attr(ATTR_REQ_TRANSPORT, &[17, 0, 0, 0]);
    let user_attr = stun_attr(ATTR_USERNAME, username.as_bytes());
    let realm_attr = stun_attr(ATTR_REALM, realm.as_bytes());
    let nonce_attr = stun_attr(ATTR_NONCE, nonce.as_bytes());

    let attrs_len = transport.len() + user_attr.len() + realm_attr.len() + nonce_attr.len();
    let mut msg = stun_header(ALLOCATE_REQUEST, attrs_len as u16, &tid);
    msg.extend_from_slice(&transport);
    msg.extend_from_slice(&user_attr);
    msg.extend_from_slice(&realm_attr);
    msg.extend_from_slice(&nonce_attr);

    append_integrity(&mut msg, username, realm, password);
    (msg, tid)
}

pub fn build_create_permission(
    peer: SocketAddr,
    username: &str,
    password: &str,
    realm: &str,
    nonce: &str,
) -> (Vec<u8>, [u8; 12]) {
    let tid = gen_tid();

    let peer_val = xor_peer_addr_value(peer);
    let peer_attr = stun_attr(ATTR_XOR_PEER_ADDR, &peer_val);
    let user_attr = stun_attr(ATTR_USERNAME, username.as_bytes());
    let realm_attr = stun_attr(ATTR_REALM, realm.as_bytes());
    let nonce_attr = stun_attr(ATTR_NONCE, nonce.as_bytes());

    let attrs_len = peer_attr.len() + user_attr.len() + realm_attr.len() + nonce_attr.len();
    let mut msg = stun_header(CREATE_PERM_REQUEST, attrs_len as u16, &tid);
    msg.extend_from_slice(&peer_attr);
    msg.extend_from_slice(&user_attr);
    msg.extend_from_slice(&realm_attr);
    msg.extend_from_slice(&nonce_attr);

    append_integrity(&mut msg, username, realm, password);
    (msg, tid)
}

pub fn build_channel_bind(
    peer: SocketAddr,
    channel: u16,
    username: &str,
    password: &str,
    realm: &str,
    nonce: &str,
) -> (Vec<u8>, [u8; 12]) {
    let tid = gen_tid();

    let mut ch_data = Vec::new();
    ch_data.extend_from_slice(&channel.to_be_bytes());
    ch_data.extend_from_slice(&[0u8; 2]); // RFFU
    let ch_attr = stun_attr(ATTR_CHANNEL_NUMBER, &ch_data);

    let peer_val = xor_peer_addr_value(peer);
    let peer_attr = stun_attr(ATTR_XOR_PEER_ADDR, &peer_val);
    let user_attr = stun_attr(ATTR_USERNAME, username.as_bytes());
    let realm_attr = stun_attr(ATTR_REALM, realm.as_bytes());
    let nonce_attr = stun_attr(ATTR_NONCE, nonce.as_bytes());

    let attrs_len =
        ch_attr.len() + peer_attr.len() + user_attr.len() + realm_attr.len() + nonce_attr.len();
    let mut msg = stun_header(CHANNEL_BIND_REQUEST, attrs_len as u16, &tid);
    msg.extend_from_slice(&ch_attr);
    msg.extend_from_slice(&peer_attr);
    msg.extend_from_slice(&user_attr);
    msg.extend_from_slice(&realm_attr);
    msg.extend_from_slice(&nonce_attr);

    append_integrity(&mut msg, username, realm, password);
    (msg, tid)
}

pub fn build_send_indication(peer: SocketAddr, data: &[u8]) -> Vec<u8> {
    let tid = gen_tid();
    let peer_val = xor_peer_addr_value(peer);
    let peer_attr = stun_attr(ATTR_XOR_PEER_ADDR, &peer_val);
    let data_attr = stun_attr(ATTR_DATA, data);

    let attrs_len = (peer_attr.len() + data_attr.len()) as u16;
    let mut msg = stun_header(SEND_INDICATION, attrs_len, &tid);
    msg.extend_from_slice(&peer_attr);
    msg.extend_from_slice(&data_attr);
    msg
}

pub fn build_channel_data(channel: u16, data: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + data.len() + 3);
    msg.extend_from_slice(&channel.to_be_bytes());
    msg.extend_from_slice(&(data.len() as u16).to_be_bytes());
    msg.extend_from_slice(data);
    let pad = (4 - (data.len() % 4)) % 4;
    msg.extend(std::iter::repeat(0u8).take(pad));
    msg
}

pub fn build_refresh(
    username: &str,
    password: &str,
    realm: &str,
    nonce: &str,
    lifetime: u32,
) -> (Vec<u8>, [u8; 12]) {
    let tid = gen_tid();

    let lt_attr = stun_attr(ATTR_LIFETIME, &lifetime.to_be_bytes());
    let user_attr = stun_attr(ATTR_USERNAME, username.as_bytes());
    let realm_attr = stun_attr(ATTR_REALM, realm.as_bytes());
    let nonce_attr = stun_attr(ATTR_NONCE, nonce.as_bytes());

    let attrs_len = lt_attr.len() + user_attr.len() + realm_attr.len() + nonce_attr.len();
    let mut msg = stun_header(REFRESH_REQUEST, attrs_len as u16, &tid);
    msg.extend_from_slice(&lt_attr);
    msg.extend_from_slice(&user_attr);
    msg.extend_from_slice(&realm_attr);
    msg.extend_from_slice(&nonce_attr);

    append_integrity(&mut msg, username, realm, password);
    (msg, tid)
}

pub fn build_binding_request() -> (Vec<u8>, [u8; 12]) {
    let tid = gen_tid();
    let msg = stun_header(BINDING_REQUEST, 0, &tid);
    (msg, tid)
}

// ================ Parsing ================

pub fn parse_stun(data: &[u8]) -> Result<StunMessage, String> {
    if data.len() < HEADER_SIZE {
        return Err("Too short".into());
    }

    // Check if ChannelData
    if (data[0] & 0xC0) != 0 {
        return Err("ChannelData".into());
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    let length = u16::from_be_bytes([data[2], data[3]]) as usize;

    let mut tid = [0u8; 12];
    tid.copy_from_slice(&data[8..20]);

    let mut attrs = Vec::new();
    let mut offset = HEADER_SIZE;
    let end = std::cmp::min(HEADER_SIZE + length, data.len());

    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > end {
            break;
        }

        let value = data[offset..offset + attr_len].to_vec();
        attrs.push((attr_type, value));

        offset += attr_len;
        let pad = (4 - (attr_len % 4)) % 4;
        offset += pad;
    }

    Ok(StunMessage {
        msg_type,
        transaction_id: tid,
        attributes: attrs,
    })
}

pub fn extract_xor_relayed_addr(msg: &StunMessage) -> Option<SocketAddr> {
    let val = msg.get_attr(ATTR_XOR_RELAYED_ADDR)?;
    if val.len() < 8 {
        return None;
    }
    if val[1] != 0x01 {
        return None; // IPv4 only
    }
    let port = u16::from_be_bytes([val[2], val[3]]) ^ ((STUN_MAGIC >> 16) as u16);
    let ip = u32::from_be_bytes([val[4], val[5], val[6], val[7]]) ^ STUN_MAGIC;
    Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
}

pub fn extract_error_code(msg: &StunMessage) -> Option<(u16, String)> {
    let val = msg.get_attr(ATTR_ERROR_CODE)?;
    if val.len() < 4 {
        return None;
    }
    let class = (val[2] & 0x07) as u16;
    let number = val[3] as u16;
    let code = class * 100 + number;
    let reason = if val.len() > 4 {
        String::from_utf8_lossy(&val[4..]).into_owned()
    } else {
        String::new()
    };
    Some((code, reason))
}

/// Извлекает realm и nonce из STUN-ответа.
pub fn extract_realm_nonce(msg: &StunMessage) -> (Option<String>, Option<String>) {
    (
        msg.get_string_attr(ATTR_REALM),
        msg.get_string_attr(ATTR_NONCE),
    )
}

/// Проверяет, является ли пакет ChannelData.
pub fn is_channel_data(data: &[u8]) -> bool {
    data.len() >= 4 && (data[0] & 0xC0) != 0
}

/// Извлекает payload из ChannelData.
pub fn parse_channel_data(data: &[u8]) -> Option<(u16, &[u8])> {
    if data.len() < 4 {
        return None;
    }
    if (data[0] & 0xC0) == 0 {
        return None;
    }
    let channel = u16::from_be_bytes([data[0], data[1]]);
    let data_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + data_len {
        return None;
    }
    Some((channel, &data[4..4 + data_len]))
}

/// Извлекает DATA из Data Indication.
pub fn extract_data_from_indication(msg: &StunMessage) -> Option<Vec<u8>> {
    msg.get_attr(ATTR_DATA).map(|v| v.to_vec())
}