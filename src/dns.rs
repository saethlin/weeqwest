use crate::Error;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Instant;

pub struct DnsCache {
    addrs: HashMap<String, DnsEntry>,
}

#[derive(Clone)]
struct DnsEntry {
    address: IpAddr,
    expiration: Instant,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            addrs: HashMap::new(),
        }
    }

    pub fn lookup(&mut self, host: &str) -> Result<IpAddr, Error> {
        let now = Instant::now();
        match self.addrs.get_mut(host) {
            Some(entry) => {
                // If the cache entry expired
                if now > entry.expiration {
                    *entry = resolve(&host)?;
                }
                Ok(entry.address)
            }
            None => {
                let entry = resolve(&host)?;
                self.addrs.insert(host.to_string(), entry.clone());
                Ok(entry.address)
            }
        }
    }
}

// TODO: Currently only works on ipv4 addrs
fn resolve(domain: &str) -> std::io::Result<DnsEntry> {
    let sock = UdpSocket::bind("0.0.0.0:0").expect("socket couldn't open");
    sock.connect("8.8.8.8:53").expect("socket couldn't connect");
    let mut message = Vec::with_capacity(100);
    // UDP header
    message.extend_from_slice(&[
        170, 170, // id
        1, 0, // query parameters
        0, 1, // number of questions
        0, 0, // number of answers,
        0, 0, // number of authority records,
        0, 0, // number of additional record,
    ]);

    for element in domain.split('.') {
        message.push(element.len() as u8);
        message.extend_from_slice(element.as_bytes());
    }
    message.push(0);

    // QTYPE, QCLASS
    message.extend_from_slice(&[0, 1, 0, 1]);

    sock.send(&message).expect("couldn't send data");

    let mut response = vec![0; 1024];

    let bytes_read = sock.recv(response.as_mut_slice()).expect("read failed");
    response.truncate(bytes_read);

    let answer = &response[message.len()..];
    let ttl = ((answer[6] as u64) << 24)
        + ((answer[7] as u64) << 16)
        + ((answer[8] as u64) << 8)
        + answer[9] as u64;
    let rdlength = ((answer[10] as u16) << 8) + (answer[11] as u16);

    assert_eq!(
        rdlength, 4,
        "Expected an IPv4 address from DNS query, got something else"
    );

    Ok(DnsEntry {
        address: IpAddr::V4(Ipv4Addr::new(
            answer[12], answer[13], answer[14], answer[15],
        )),
        expiration: Instant::now() + std::time::Duration::new(ttl, 0),
    })
}
