use super::packet::icmp::ICMP;
use super::Error;

use dns_lookup;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{
    icmp_packet_iter, transport_channel,
    TransportChannelType::Layer4,
    TransportProtocol::{Ipv4, Ipv6},
};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

pub fn ping(v: bool, address: &str, timeout: Duration) -> Result<(IpAddr, String), Error> {
    // get ip
    let (ip, host) = match IpAddr::from_str(address) {
        // lookup hostname (if it is possible)
        Ok(ip) => (ip, dns_lookup::lookup_addr(&ip).unwrap_or(ip.to_string())),
        Err(_) => {
            // lookup IP
            match dns_lookup::lookup_host(address) {
                // invalid address
                Err(_) => return Err(Error::InvalidAddress(address.to_owned())),
                Ok(ips) => {
                    // first ip address
                    let lookup = ips.get(0);
                    if lookup.is_none() {
                        return Err(Error::InvalidAddress(address.to_owned()));
                    }
                    let ip = lookup.unwrap();
                    // double check the address
                    match dns_lookup::lookup_addr(ip) {
                        Ok(host) => (host.parse::<IpAddr>().unwrap_or(*ip), address.to_string()),
                        Err(_) => (ip.to_owned(), address.to_string()),
                    }
                }
            }
        }
    };
    // check protocol
    let protocol = if ip.is_ipv4() {
        Layer4(Ipv4(IpNextHeaderProtocols::Icmp))
    } else {
        Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6))
    };
    // build transport
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(_) => return Err(Error::PrivilegeRequired),
    };
    // set ttl (only IPv4)
    if ip.is_ipv4() {
        tx.set_ttl(u8::MAX).unwrap();
    }
    // build and send package
    if v {
        println!("* Pinging {} ({}) 32 bytes of data.", ip, host)
    }
    let mut packet = ICMP::new(ip);
    let status = if ip.is_ipv4() {
        packet.send_v4(&mut tx)
    } else {
        packet.send_v6(&mut tx)
    };
    if status.is_err() {
        let err = status.unwrap_err();
        if v {
            println!("* Error connecting to {}: {}", ip, err);
        }
        return Err(Error::Unknown(err.to_string()));
    }
    // get the response
    let mut responses = icmp_packet_iter(&mut rx);
    let recv = responses.next_with_timeout(timeout);
    if recv.is_err() {
        if v {
            println!(
                "* Timeout connecting to {} ({}s): {}",
                ip,
                timeout.as_secs_f64(),
                recv.unwrap_err().to_string()
            );
        }
        return Err(Error::Timeout(ip, timeout));
    }
    // reading the data
    let data = recv.unwrap();
    let (recv_pkg, recv_addr) = match data.ok_or(Error::NoResponse(ip)) {
        Ok((pkg, ipaddr)) => (pkg, ipaddr),
        Err(err) => {
            if v {
                println!("* Error reading data from {}: {}", ip, err);
            }
            return Err(Error::NoResponse(ip));
        }
    };
    // check package type
    match recv_pkg.get_icmp_type() {
        IcmpTypes::EchoRequest => {
            // check the payload
            if v {
                println!("* {} is up!", recv_addr);
            }
            Ok((recv_addr, host))
        }
        IcmpTypes::EchoReply => {
            if v {
                println!("* {} is up!", recv_addr);
            }
            Ok((recv_addr, host))
        }
        IcmpTypes::DestinationUnreachable => {
            if v {
                println!("* {} is unreachable", recv_addr);
            }
            Err(Error::DestinationUnreachable(recv_addr))
        }
        IcmpTypes::TimeExceeded => {
            if v {
                println!(
                    "* Timeout connecting to {} ({}s)",
                    recv_addr,
                    timeout.as_secs_f64()
                );
            }
            Err(Error::NoResponse(recv_addr))
        }
        err => {
            if v {
                println!(
                    "* Unknown ICMP packet received from {}: {:?}",
                    recv_addr, err
                );
            }
            Err(Error::Unknown(format!("{:?} received", err)))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // test template
    fn ping_test(ip: &str, _result: (&str, &str)) {
        assert_eq!(
            true,
            match ping(false, ip, Duration::from_secs(1)) {
                Ok(result) => result.0.to_string() == _result.0.to_owned() && result.1 == _result.1,
                _ => false,
            }
        )
    }

    // IPv4
    #[test]
    fn ping_ipv4_loopback() {
        ping_test("127.0.0.1", ("127.0.0.1", "localhost"))
    }

    #[test]
    fn ping_ipv4_local() {
        ping_test("192.168.0.1", ("192.168.0.1", "_gateway"))
    }

    #[test]
    fn ping_ipv4_external() {
        ping_test("1.1.1.1", ("1.1.1.1", "one.one.one.one"))
    }

    // IPv6
    #[test]
    fn ping_ipv6_loopback() {
        ping_test("::1", ("::1", "localhost"))
    }

    #[test]
    fn ping_ipv6_external() {
        ping_test(
            "2001:4860:4860::8888",
            ("2001:4860:4860::8888", "google.com"),
        )
    }

    // Host

    #[test]
    fn ping_localhost() {
        ping_test("localhost", ("127.0.0.1", "localhost"))
    }

    #[test]
    fn ping_domain() {
        ping_test("example.com", ("93.184.216.34", "example.com"))
    }
}
