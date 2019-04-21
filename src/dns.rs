use crate::Error;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::Instant;

macro_rules! mask {
    ($byte:expr, $($mask:expr),*) => {
        {
            let value = $byte;
            ($( value & $mask , )*)
        }
    };
    ($byte:expr, $($mask:expr),*,) => {
        {
            let value = $byte;
            ($( value & $mask , )*)
        }
    };
}

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
        if host == "localhost" {
            return Ok(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        }
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

    sock.send(&message).expect("couldn't send data");

    let mut response = vec![0; 1024];

    let bytes_read = sock.recv(response.as_mut_slice()).expect("read failed");
    response.truncate(bytes_read);
    let mut response = std::io::Cursor::new(response);

    if response.read2()? != [170, 170] {
        return err("DNS response had incorrect id");
    }

    let (is_response, opcode, _is_authoritative, is_truncated, _recursion_desired) = mask!(
        response.read_byte()?,
        0b1000_0000,
        0b0111_1000,
        0b0000_0100,
        0b0000_0010,
        0b0000_0001,
    );

    if is_response == 0 {
        return err("Got a DNS dataframe that isn't a response");
    }
    if opcode != 0 {
        return err("DNS opcode must be 0 (QUERY)");
    }
    if is_truncated == 1 {
        return err("DNS response was truncated");
    }

    let (_rescursion_available, zero_bytes, response_code) =
        mask!(response.read_byte()?, 0b1000_0000, 0b0111_0000, 0b0000_1111,);

    if zero_bytes != 0 {
        return err("Required zero bytes in DNS response are not zero");
    }
    if response_code != 0 {
        return err("DNS server error");
    }

    let question_count = u16::from_be_bytes(response.read2()?);
    if question_count != 1 {
        return err("DNS response contains incorrect question count");
    }
    let answer_count = u16::from_be_bytes(response.read2()?);
    if answer_count == 0 {
        return err("DNS response contains no answers");
    }
    let _ns_count = u16::from_be_bytes(response.read2()?);
    let _ar_count = u16::from_be_bytes(response.read2()?);

    let question_name = read_name(&mut response)?;

    let qtype = u16::from_be_bytes(response.read2()?);
    let qclass = u16::from_be_bytes(response.read2()?);

    if qtype != 1 {
        return err("DNS response qtype must be 1 (host address)");
    }
    if qclass != 1 {
        return err("DNS response qclass must be 1 (internet)");
    }

    let start_byte = response.peek()?;
    let answer_name = if (start_byte & 0b1100_0000) == 0b1100_0000 {
        // We got a pointer
        let pointer = u16::from_be_bytes(response.read2()?) & !0b11000000_00000000;
        let old_position = response.position();
        response.set_position(u64::from(pointer));
        let name = read_name(&mut response)?;
        response.set_position(old_position); // Advance past the pointer
        name
    } else {
        read_name(&mut response)?
    };

    if question_name != answer_name {
        return err("DNS answer domain does not match question domain");
    }

    let qtype = u16::from_be_bytes(response.read2()?);
    let qclass = u16::from_be_bytes(response.read2()?);

    if qtype != 1 {
        return err("DNS response qtype must be 1 (host address)");
    }
    if qclass != 1 {
        return err("DNS response qclass must be 1 (internet)");
    }

    let ttl = u32::from_be_bytes(response.read4()?);

    let rdlength = u16::from_be_bytes(response.read2()?);

    if rdlength == 4 {
        let ip = response.read4()?;
        Ok(DnsEntry {
            address: IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            expiration: Instant::now() + std::time::Duration::from_secs(u64::from(ttl)),
        })
    } else {
        panic!("rdlength must be 4");
    }
}

mod tests {
    #[test]
    fn resolve_ipv6() {
        let addr = super::resolve("google.com").unwrap();
        println!("{:?}", addr);
    }
}

fn err(message: &'static str) -> io::Result<DnsEntry> {
    Err(io::Error::new(io::ErrorKind::InvalidData, message))
}

fn read_name(response: &mut std::io::Cursor<Vec<u8>>) -> io::Result<String> {
    let mut name = String::new();
    let mut name_len = response.read_byte()?;
    loop {
        for _ in 0..name_len {
            name.push(response.read_byte()? as char);
        }
        name_len = response.read_byte()?;
        if name_len > 0 {
            name.push('.');
        } else {
            break;
        }
    }
    Ok(name)
}

trait CursorExt: io::Read {
    fn read_byte(&mut self) -> io::Result<u8> {
        let mut byte = [0];
        self.read_exact(&mut byte)?;
        Ok(byte[0])
    }

    fn read2(&mut self) -> io::Result<[u8; 2]> {
        let mut bytes = [0; 2];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn read4(&mut self) -> io::Result<[u8; 4]> {
        let mut bytes = [0; 4];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn peek(&mut self) -> io::Result<u8>;
}

impl CursorExt for io::Cursor<Vec<u8>> {
    fn peek(&mut self) -> io::Result<u8> {
        self.get_ref()
            .get(self.position() as usize)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "unable to peek cursor"))
    }
}
