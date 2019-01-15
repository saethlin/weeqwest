use crate::Error;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Instant;

pub struct DnsCache {
    addrs: HashMap<String, DnsEntry>,
}

#[derive(Clone, Debug)]
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
        // Check if we already have an entry for this host
        match self.addrs.get_mut(host) {
            Some(entry) => {
                // If the cache entry expired, replace it
                if Instant::now() > entry.expiration {
                    *entry = resolve(&host)?;
                }
                Ok(entry.address)
            }
            // If we don't, look it up and add a new cache entry
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
    let sock = UdpSocket::bind("0.0.0.0:0").expect("UDP socket for DNS resolution couldn't open");
    sock.connect("8.8.8.8:53")
        .expect("UDP socket for DNS resolution couldn't connect to 8.8.8.8:53");
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

    println!("outgoing message length: {}", message.len());
    sock.send(&message).expect("couldn't send data");

    let mut response = vec![0; 1024];

    let bytes_read = sock.recv(response.as_mut_slice()).expect("read failed");
    response.truncate(bytes_read);

    println!("read response length: {}", bytes_read);

    assert!(
        response[0] == 170 && response[1] == 170,
        "DNS response had incorrect id"
    );

    let is_response = (0b10000000 & response[2]) > 0;
    let opcode = 0b01111000 & response[3];
    let is_authoritative_answer = 0b00000100 & response[3];
    let is_truncated = 0b00000010 & response[3];
    let recursion_desired = 0b00000001 & response[3];
    let recursion_available = 0b10000000 & response[4];
    assert_eq!(
        0b01110000 & response[4],
        0,
        "Required zero bytes in DNS response are not zero"
    );
    let response_code = 0b00001111 & response[4];

    assert_eq!(
        response_code, 0,
        "DNS response code indicates an error, should be 0"
    );

    let question_count = u16::from_le_bytes([response[5], response[6]]);
    let answer_count = u16::from_le_bytes([response[7], response[8]]);
    let ns_count = u16::from_le_bytes([response[9], response[10]]);
    let ar_count = u16::from_le_bytes([response[11], response[12]]);

    let mut first_name = String::new();
    let mut name_end = 13;
    while response[name_end] != 0 {
        first_name.push(response[name_end] as char);
        name_end += 1;
    }

    println!("response name: {}", first_name);

    // response[name_end] == 0, the null terminator for the name

    println!("{:?}", &response[name_end..name_end + 6]);

    let qtype = u16::from_le_bytes([response[name_end + 1], response[name_end + 2]]);
    let qclass = u16::from_le_bytes([response[name_end + 3], response[name_end + 4]]);

    assert!(
        qtype == 1 || qtype == 256,
        "DNS response qtype is not 1 (host address) or 256 (request for all records)"
    );
    assert!(
        qclass == 1 || qclass == 256,
        "DNS response qclass is not 1 (internet) or 256 (any class)"
    );

    println!(
        "Asked {} questions, got {} answers",
        question_count, answer_count
    );

    let next_name = &response[name_end + 5..];

    for v in &response[name_end + 5..name_end + 11] {
        println!("{:08b}", *v);
    }

    name_end += 6; // wtf does this skip over
    println!("{}, {}", name_end + 5, message.len());

    // Parse the TTL information for the first record
    let ttl = ((response[name_end + 5] as u64) << 24)
        + ((response[name_end + 6] as u64) << 16)
        + ((response[name_end + 7] as u64) << 8)
        + response[name_end + 8] as u64;
    println!("ttl: {}", ttl);
    let rdlength = ((response[name_end + 9] as u16) << 8) + (response[name_end + 10] as u16);
    let ip = &response[name_end + 11..name_end + 11 + rdlength as usize];

    assert_eq!(
        rdlength, 4,
        "Expected an IPv4 address from DNS query, got something else"
    );

    Ok(DnsEntry {
        address: IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
        expiration: Instant::now() + std::time::Duration::new(ttl, 0),
    })
}

mod tests {
    #[test]
    fn resolve_ipv6() {
        let addr = super::resolve("test-ipv6.com").unwrap();
        println!("{:?}", addr);
    }
}
