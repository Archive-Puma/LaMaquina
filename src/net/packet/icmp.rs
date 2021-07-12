use pnet::packet::icmp::{echo_request::MutableEchoRequestPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::Packet;
use pnet::transport::TransportSender;
use pnet::util::checksum;
use rand::random;
use std::net::IpAddr;

pub struct ICMP {
    id: u16,
    address: IpAddr,
    sequence: u16,
    pub seen: bool,
}

#[allow(dead_code)]
impl ICMP {
    pub fn new(address: IpAddr) -> ICMP {
        let mut id = 0;
        if address.is_ipv4() {
            id = random::<u16>();
        }
        ICMP {
            id,
            address,
            sequence: 0,
            seen: false,
        }
    }

    pub fn get_id(&mut self) -> u16 {
        self.id
    }

    pub fn get_address(&mut self) -> IpAddr {
        self.address
    }

    pub fn get_sequence(&mut self) -> u16 {
        self.sequence
    }

    pub fn next(&mut self) -> u16 {
        self.sequence += 1;
        self.sequence
    }

    pub fn send_v4(&mut self, tr: &mut TransportSender) -> Result<usize, std::io::Error> {
        let mut buffer: Vec<u8> = vec![0; 64];
        let mut packet = MutableEchoRequestPacket::new(&mut buffer[..]).unwrap();
        packet.set_icmp_type(IcmpTypes::EchoRequest);
        packet.set_identifier(self.id);
        packet.set_sequence_number(self.next());
        packet.set_checksum(checksum(packet.packet(), 1));
        tr.send_to(packet, self.address)
    }

    pub fn send_v6(&mut self, tr: &mut TransportSender) -> Result<usize, std::io::Error> {
        let mut buffer: Vec<u8> = vec![0; 64];
        let mut packet = MutableIcmpv6Packet::new(&mut buffer[..]).unwrap();
        packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
        packet.set_checksum(checksum(packet.packet(), 1));
        tr.send_to(packet, self.address)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ipv4() {
        let mut packet = ICMP::new("127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(packet.get_address().to_string(), "127.0.0.1");
        assert_ne!(packet.id, 0);
        assert_eq!(packet.get_sequence(), 0);
        packet.next();
        assert_eq!(packet.get_sequence(), 1);
        assert_eq!(packet.seen, false);
    }

    #[test]
    fn ipv6() {
        let mut packet = ICMP::new("::1".parse::<IpAddr>().unwrap());
        assert_eq!(packet.get_address().to_string(), "::1");
        assert_eq!(packet.id, 0);
        assert_eq!(packet.get_sequence(), 0);
        packet.next();
        assert_eq!(packet.get_sequence(), 1);
        assert_eq!(packet.seen, false);
    }
}
