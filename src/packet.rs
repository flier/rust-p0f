use std::convert::TryInto;

use failure::{bail, err_msg, Error};

use pnet::packet::{
    ethernet::{EtherType, EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Flags, Ipv4Packet},
    ipv6::Ipv6Packet,
    tcp::{TcpFlags, TcpOptionNumbers::*, TcpOptionPacket, TcpPacket},
    vlan::VlanPacket,
    Packet, PacketSize,
};

use crate::tcp::{IpVersion, PayloadSize, Quirk, Signature, TcpOption, WindowSize, TTL};

impl Signature {
    pub fn extract(packet: &[u8]) -> Result<Self, Error> {
        EthernetPacket::new(packet)
            .ok_or_else(|| err_msg("ethernet packet too short"))
            .and_then(|packet| visit_ethernet(packet.get_ethertype(), packet.payload()))
    }
}

fn visit_ethernet(ethertype: EtherType, payload: &[u8]) -> Result<Signature, Error> {
    match ethertype {
        EtherTypes::Vlan => VlanPacket::new(payload)
            .ok_or_else(|| err_msg("vlan packet too short"))
            .and_then(visit_vlan),

        EtherTypes::Ipv4 => Ipv4Packet::new(payload)
            .ok_or_else(|| err_msg("ipv4 packet too short"))
            .and_then(visit_ipv4),

        EtherTypes::Ipv6 => Ipv6Packet::new(payload)
            .ok_or_else(|| err_msg("ipv6 packet too short"))
            .and_then(visit_ipv6),

        ty => bail!("unsupport ethernet type: {}", ty),
    }
}

fn visit_vlan(packet: VlanPacket) -> Result<Signature, Error> {
    visit_ethernet(packet.get_ethertype(), packet.payload())
}

/// Congestion encountered
const IP_TOS_CE: u8 = 0x01;
/// ECN supported
const IP_TOS_ECT: u8 = 0x02;
/// Must be zero
const IP4_MBZ: u8 = 0b0100;

fn visit_ipv4(packet: Ipv4Packet) -> Result<Signature, Error> {
    if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        bail!(
            "unsuppport IPv4 packet with non-TCP payload: {}",
            packet.get_next_level_protocol()
        );
    }

    if packet.get_fragment_offset() > 0
        || (packet.get_flags() & Ipv4Flags::MoreFragments) == Ipv4Flags::MoreFragments
    {
        bail!("unsupport IPv4 fragment");
    }

    let version = IpVersion::V4;
    let ttl = TTL::Value(packet.get_ttl());
    let olen = packet.get_options_raw().len() as u8;
    let mut quirks = vec![];

    if (packet.get_ecn() & (IP_TOS_CE | IP_TOS_ECT)) != 0 {
        quirks.push(Quirk::ECN);
    }

    if (packet.get_flags() & IP4_MBZ) != 0 {
        quirks.push(Quirk::MustBeZero);
    }

    if (packet.get_flags() & Ipv4Flags::DontFragment) != 0 {
        quirks.push(Quirk::DF);

        if packet.get_identification() != 0 {
            quirks.push(Quirk::NonZeroID);
        }
    } else {
        if packet.get_identification() == 0 {
            quirks.push(Quirk::ZeroID);
        }
    }

    TcpPacket::new(packet.payload())
        .ok_or_else(|| err_msg("TCP packet too short"))
        .and_then(|packet| visit_tcp(packet, version, ttl, olen, quirks))
}

fn visit_ipv6(packet: Ipv6Packet) -> Result<Signature, Error> {
    if packet.get_next_header() != IpNextHeaderProtocols::Tcp {
        bail!(
            "unsuppport IPv6 packet with non-TCP payload: {}",
            packet.get_next_header()
        );
    }

    let version = IpVersion::V6;
    let ttl = TTL::Value(packet.get_hop_limit());
    let mut olen = 0; // TODO handle extensions
    let mut quirks = vec![];

    if packet.get_flow_label() != 0 {
        quirks.push(Quirk::FlowID);
    }
    if (packet.get_traffic_class() & (IP_TOS_CE | IP_TOS_ECT)) != 0 {
        quirks.push(Quirk::ECN);
    }

    TcpPacket::new(packet.payload())
        .ok_or_else(|| err_msg("TCP packet too short"))
        .and_then(|packet| visit_tcp(packet, version, ttl, olen, quirks))
}

fn visit_tcp(
    tcp: TcpPacket,
    version: IpVersion,
    ittl: TTL,
    olen: u8,
    mut quirks: Vec<Quirk>,
) -> Result<Signature, Error> {
    use TcpFlags::*;

    let flags = tcp.get_flags();
    let tcp_type = flags & (SYN | ACK | FIN | RST);

    if ((flags & SYN) == SYN && (flags & (FIN | RST)) != 0)
        || (flags & (FIN | RST)) == (FIN | RST)
        || tcp_type == 0
    {
        bail!("invalid TCP flags: {}", flags);
    }

    if (flags & (ECE | CWR | NS)) != 0 {
        quirks.push(Quirk::ECN);
    }
    if tcp.get_sequence() == 0 {
        quirks.push(Quirk::SeqNumZero);
    }
    if flags & ACK == ACK {
        if tcp.get_acknowledgement() == 0 {
            quirks.push(Quirk::AckNumZero);
        }
    } else {
        if tcp.get_acknowledgement() != 0 && flags & RST == 0 {
            quirks.push(Quirk::AckNumNonZero);
        }
    }
    if flags & URG == URG {
        quirks.push(Quirk::URG);
    } else {
        if tcp.get_urgent_ptr() != 0 {
            quirks.push(Quirk::NonZeroURG);
        }
    }
    if flags & PSH == PSH {
        quirks.push(Quirk::PUSH);
    }

    let mut buf = tcp.get_options_raw();
    let mut mss = None;
    let mut wscale = None;
    let mut olayout = vec![];

    while let Some(opt) = TcpOptionPacket::new(buf) {
        buf = &buf[opt.packet_size().min(buf.len())..];

        let data = opt.payload();

        match opt.get_number() {
            EOL => {
                olayout.push(TcpOption::EOL(buf.len() as u8));

                if buf.iter().any(|&b| b != 0) {
                    quirks.push(Quirk::TrailinigNonZero);
                }
            }
            NOP => {
                olayout.push(TcpOption::NOP);
            }
            MSS => {
                olayout.push(TcpOption::MSS);

                if data.len() > 2 {
                    mss = Some(u16::from_ne_bytes(data[..2].try_into()?));
                }

                if data.len() != 4 {
                    quirks.push(Quirk::OptBad);
                }
            }
            WSCALE => {
                olayout.push(TcpOption::WS);

                wscale = Some(data[0]);

                if data[0] > 14 {
                    quirks.push(Quirk::ExcessiveWindowScaling);
                }
                if data.len() != 3 {
                    quirks.push(Quirk::OptBad);
                }
            }
            SACK_PERMITTED => {
                olayout.push(TcpOption::SOK);

                if data.len() != 2 {
                    quirks.push(Quirk::OptBad);
                }
            }
            SACK => {
                olayout.push(TcpOption::SACK);

                match data.len() {
                    10 | 18 | 26 | 34 => {}
                    _ => quirks.push(Quirk::OptBad),
                }
            }
            TIMESTAMPS => {
                olayout.push(TcpOption::TS);

                if u16::from_ne_bytes(data[..4].try_into()?) == 0 {
                    quirks.push(Quirk::OwnTimestampZero);
                }

                if tcp_type == SYN && u16::from_ne_bytes(data[4..8].try_into()?) != 0 {
                    quirks.push(Quirk::PeerTimestampNonZero);
                }

                if data.len() != 10 {
                    quirks.push(Quirk::OptBad);
                }
            }
            _ => {
                olayout.push(TcpOption::Unknown(opt.get_number().0));
            }
        }
    }

    Ok(Signature {
        version,
        ittl,
        olen,
        mss,
        wsize: WindowSize::Value(tcp.get_window()),
        wscale,
        olayout,
        quirks,
        pclass: if tcp.payload().is_empty() {
            PayloadSize::Zero
        } else {
            PayloadSize::NonZero
        },
    })
}
