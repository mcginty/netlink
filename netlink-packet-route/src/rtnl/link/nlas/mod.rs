mod inet;
pub use self::inet::*;

mod inet6;
pub use self::inet6::*;

mod af_spec_inet;
pub use self::af_spec_inet::*;

mod link_infos;
pub use self::link_infos::*;

mod map;
pub use self::map::*;

mod stats;
pub use self::stats::*;

mod stats64;
pub use self::stats64::*;

mod link_state;
pub use self::link_state::*;

#[cfg(test)]
mod tests;

use std::os::unix::io::RawFd;

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};

use crate::{
    constants::*,
    nlas::{self, DefaultNla, NlaBuffer, NlasIterator},
    parsers::{parse_i32, parse_string, parse_u32, parse_u8},
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError,
    ByteVec,
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nla {
    // Vec<u8>
    Unspec(ByteVec),
    Cost(ByteVec),
    Priority(ByteVec),
    Weight(ByteVec),
    VfInfoList(ByteVec),
    VfPorts(ByteVec),
    PortSelf(ByteVec),
    PhysPortId(ByteVec),
    PhysSwitchId(ByteVec),
    Pad(ByteVec),
    Xdp(ByteVec),
    Event(ByteVec),
    NewNetnsId(ByteVec),
    IfNetnsId(ByteVec),
    CarrierUpCount(ByteVec),
    CarrierDownCount(ByteVec),
    NewIfIndex(ByteVec),
    Info(Vec<Info>),
    Wireless(ByteVec),
    ProtoInfo(ByteVec),
    /// A list of properties for the device. For additional context see the related linux kernel
    /// threads<sup>[1][1],[2][2]</sup>. In particular see [this message][defining message] from
    /// the first thread describing the design.
    ///
    /// [1]: https://lwn.net/ml/netdev/20190719110029.29466-1-jiri@resnulli.us/
    /// [2]: https://lwn.net/ml/netdev/20190930094820.11281-1-jiri@resnulli.us/
    /// [defining message]: https://lwn.net/ml/netdev/20190913145012.GB2276@nanopsycho.orion/
    PropList(ByteVec),
    /// `protodown` is a mechanism that allows protocols to hold an interface down.
    /// This field is used to specify the reason why it is held down.
    /// For additional context see the related linux kernel threads<sup>[1][1],[2][2]</sup>.
    ///
    /// [1]: https://lwn.net/ml/netdev/1595877677-45849-1-git-send-email-roopa%40cumulusnetworks.com/
    /// [2]: https://lwn.net/ml/netdev/1596242041-14347-1-git-send-email-roopa%40cumulusnetworks.com/
    ProtoDownReason(ByteVec),
    // mac address (use to be [u8; 6] but it turns out MAC != HW address, for instance for IP over
    // GRE where it's an IPv4!)
    Address(ByteVec),
    Broadcast(ByteVec),
    /// Permanent hardware address of the device. The provides the same information
    /// as the ethtool ioctl interface.
    PermAddress(ByteVec),

    // string
    // FIXME: for empty string, should we encode the NLA as \0 or should we not set a payload? It
    // seems that for certain attriutes, this matter:
    // https://elixir.bootlin.com/linux/v4.17-rc5/source/net/core/rtnetlink.c#L1660
    IfName(String),
    Qdisc(String),
    IfAlias(String),
    PhysPortName(String),
    /// Alternate name for the device.
    /// For additional context see the related linux kernel threads<sup>[1][1],[2][2]</sup>.
    ///
    /// [1]: https://lwn.net/ml/netdev/20190719110029.29466-1-jiri@resnulli.us/
    /// [2]: https://lwn.net/ml/netdev/20190930094820.11281-1-jiri@resnulli.us/
    AltIfName(String),
    // byte
    Mode(u8),
    Carrier(u8),
    ProtoDown(u8),
    // u32
    Mtu(u32),
    Link(u32),
    Master(u32),
    TxQueueLen(u32),
    NetNsPid(u32),
    NumVf(u32),
    Group(u32),
    NetNsFd(RawFd),
    ExtMask(u32),
    Promiscuity(u32),
    NumTxQueues(u32),
    NumRxQueues(u32),
    CarrierChanges(u32),
    GsoMaxSegs(u32),
    GsoMaxSize(u32),
    /// The minimum MTU for the device.
    /// For additional context see the related [linux kernel message][1].
    ///
    /// [1]: https://lwn.net/ml/netdev/20180727204323.19408-3-sthemmin%40microsoft.com/
    MinMtu(u32),
    /// The maximum MTU for the device.
    /// For additional context see the related [linux kernel message][1].
    ///
    /// [1]: https://lwn.net/ml/netdev/20180727204323.19408-3-sthemmin%40microsoft.com/
    MaxMtu(u32),
    // i32
    NetnsId(i32),
    // custom
    OperState(State),
    Stats(ByteVec),
    Stats64(ByteVec),
    Map(ByteVec),
    // AF_SPEC (the type of af_spec depends on the interface family of the message)
    AfSpecInet(Vec<AfSpecInet>),
    // AfSpecBridge(Vec<AfSpecBridgeNla>),
    AfSpecBridge(ByteVec),
    AfSpecUnknown(ByteVec),
    Other(DefaultNla),
}

impl nlas::Nla for Nla {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::Nla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes)
                | Cost(ref bytes)
                | Priority(ref bytes)
                | Weight(ref bytes)
                | VfInfoList(ref bytes)
                | VfPorts(ref bytes)
                | PortSelf(ref bytes)
                | PhysPortId(ref bytes)
                | PhysSwitchId(ref bytes)
                | Pad(ref bytes)
                | Xdp(ref bytes)
                | Event(ref bytes)
                | NewNetnsId(ref bytes)
                | IfNetnsId(ref bytes)
                | Wireless(ref bytes)
                | ProtoInfo(ref bytes)
                | CarrierUpCount(ref bytes)
                | CarrierDownCount(ref bytes)
                | NewIfIndex(ref bytes)
                | Address(ref bytes)
                | Broadcast(ref bytes)
                | PermAddress(ref bytes)
                | AfSpecUnknown(ref bytes)
                | AfSpecBridge(ref bytes)
                | Map(ref bytes)
                | PropList(ref bytes)
                | ProtoDownReason(ref bytes)
                => bytes.len(),

            // strings: +1 because we need to append a nul byte
            IfName(ref string)
                | Qdisc(ref string)
                | IfAlias(ref string)
                | PhysPortName(ref string)
                | AltIfName(ref string)
                => string.as_bytes().len() + 1,

            // u8
            Mode(_)
                | Carrier(_)
                | ProtoDown(_)
                => 1,

            // u32 and i32
            Mtu(_)
                | Link(_)
                | Master(_)
                | TxQueueLen(_)
                | NetNsPid(_)
                | NumVf(_)
                | Group(_)
                | NetNsFd(_)
                | ExtMask(_)
                | Promiscuity(_)
                | NumTxQueues(_)
                | NumRxQueues(_)
                | CarrierChanges(_)
                | GsoMaxSegs(_)
                | GsoMaxSize(_)
                | NetnsId(_)
                | MinMtu(_)
                | MaxMtu(_) => 4,

            // Defaults
            OperState(_) => 1,
            Stats(_) => LINK_STATS_LEN,
            Stats64(_) => LINK_STATS64_LEN,
            Info(ref nlas) => nlas.as_slice().buffer_len(),
            AfSpecInet(ref nlas) => nlas.as_slice().buffer_len(),
            // AfSpecBridge(ref nlas) => nlas.as_slice().buffer_len(),
            Other(ref attr)  => attr.value_len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Nla::*;
        match *self {
            // Vec<u8>
            Unspec(ref bytes)
                | Cost(ref bytes)
                | Priority(ref bytes)
                | Weight(ref bytes)
                | VfInfoList(ref bytes)
                | VfPorts(ref bytes)
                | PortSelf(ref bytes)
                | PhysPortId(ref bytes)
                | PhysSwitchId(ref bytes)
                | Wireless(ref bytes)
                | ProtoInfo(ref bytes)
                | Pad(ref bytes)
                | Xdp(ref bytes)
                | Event(ref bytes)
                | NewNetnsId(ref bytes)
                | IfNetnsId(ref bytes)
                | CarrierUpCount(ref bytes)
                | CarrierDownCount(ref bytes)
                | NewIfIndex(ref bytes)
                // mac address (could be [u8; 6] or [u8; 4] for example. Not sure if we should have
                // a separate type for them
                | Address(ref bytes)
                | Broadcast(ref bytes)
                | PermAddress(ref bytes)
                | AfSpecUnknown(ref bytes)
                | AfSpecBridge(ref bytes)
                | Stats(ref bytes)
                | Stats64(ref bytes)
                | Map(ref bytes)
                | PropList(ref bytes)
                | ProtoDownReason(ref bytes)
                => buffer.copy_from_slice(bytes.as_slice()),

            // String
            IfName(ref string)
                | Qdisc(ref string)
                | IfAlias(ref string)
                | PhysPortName(ref string)
                | AltIfName(ref string)
                => {
                    buffer[..string.len()].copy_from_slice(string.as_bytes());
                    buffer[string.len()] = 0;
                }

            // u8
            Mode(ref val)
                | Carrier(ref val)
                | ProtoDown(ref val)
                => buffer[0] = *val,

            // u32
            Mtu(ref value)
                | Link(ref value)
                | Master(ref value)
                | TxQueueLen(ref value)
                | NetNsPid(ref value)
                | NumVf(ref value)
                | Group(ref value)
                | ExtMask(ref value)
                | Promiscuity(ref value)
                | NumTxQueues(ref value)
                | NumRxQueues(ref value)
                | CarrierChanges(ref value)
                | GsoMaxSegs(ref value)
                | GsoMaxSize(ref value)
                | MinMtu(ref value)
                | MaxMtu(ref value)
                => NativeEndian::write_u32(buffer, *value),

            NetnsId(ref value)
                | NetNsFd(ref value)
                => NativeEndian::write_i32(buffer, *value),

            OperState(state) => buffer[0] = state.into(),
            Info(ref nlas) => nlas.as_slice().emit(buffer),
            AfSpecInet(ref nlas) => nlas.as_slice().emit(buffer),
            // AfSpecBridge(ref nlas) => nlas.as_slice().emit(buffer),
            // default nlas
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match *self {
            // Vec<u8>
            Unspec(_) => IFLA_UNSPEC,
            Cost(_) => IFLA_COST,
            Priority(_) => IFLA_PRIORITY,
            Weight(_) => IFLA_WEIGHT,
            VfInfoList(_) => IFLA_VFINFO_LIST,
            VfPorts(_) => IFLA_VF_PORTS,
            PortSelf(_) => IFLA_PORT_SELF,
            PhysPortId(_) => IFLA_PHYS_PORT_ID,
            PhysSwitchId(_) => IFLA_PHYS_SWITCH_ID,
            Info(_) => IFLA_LINKINFO,
            Wireless(_) => IFLA_WIRELESS,
            ProtoInfo(_) => IFLA_PROTINFO,
            Pad(_) => IFLA_PAD,
            Xdp(_) => IFLA_XDP,
            Event(_) => IFLA_EVENT,
            NewNetnsId(_) => IFLA_NEW_NETNSID,
            IfNetnsId(_) => IFLA_IF_NETNSID,
            CarrierUpCount(_) => IFLA_CARRIER_UP_COUNT,
            CarrierDownCount(_) => IFLA_CARRIER_DOWN_COUNT,
            NewIfIndex(_) => IFLA_NEW_IFINDEX,
            PropList(_) => IFLA_PROP_LIST,
            ProtoDownReason(_) => IFLA_PROTO_DOWN_REASON,
            // Mac address
            Address(_) => IFLA_ADDRESS,
            Broadcast(_) => IFLA_BROADCAST,
            PermAddress(_) => IFLA_PERM_ADDRESS,
            // String
            IfName(_) => IFLA_IFNAME,
            Qdisc(_) => IFLA_QDISC,
            IfAlias(_) => IFLA_IFALIAS,
            PhysPortName(_) => IFLA_PHYS_PORT_NAME,
            AltIfName(_) => IFLA_ALT_IFNAME,
            // u8
            Mode(_) => IFLA_LINKMODE,
            Carrier(_) => IFLA_CARRIER,
            ProtoDown(_) => IFLA_PROTO_DOWN,
            // u32
            Mtu(_) => IFLA_MTU,
            Link(_) => IFLA_LINK,
            Master(_) => IFLA_MASTER,
            TxQueueLen(_) => IFLA_TXQLEN,
            NetNsPid(_) => IFLA_NET_NS_PID,
            NumVf(_) => IFLA_NUM_VF,
            Group(_) => IFLA_GROUP,
            NetNsFd(_) => IFLA_NET_NS_FD,
            ExtMask(_) => IFLA_EXT_MASK,
            Promiscuity(_) => IFLA_PROMISCUITY,
            NumTxQueues(_) => IFLA_NUM_TX_QUEUES,
            NumRxQueues(_) => IFLA_NUM_RX_QUEUES,
            CarrierChanges(_) => IFLA_CARRIER_CHANGES,
            GsoMaxSegs(_) => IFLA_GSO_MAX_SEGS,
            GsoMaxSize(_) => IFLA_GSO_MAX_SIZE,
            MinMtu(_) => IFLA_MIN_MTU,
            MaxMtu(_) => IFLA_MAX_MTU,
            // i32
            NetnsId(_) => IFLA_LINK_NETNSID,
            // custom
            OperState(_) => IFLA_OPERSTATE,
            Map(_) => IFLA_MAP,
            Stats(_) => IFLA_STATS,
            Stats64(_) => IFLA_STATS64,
            AfSpecInet(_) | AfSpecBridge(_) | AfSpecUnknown(_) => IFLA_AF_SPEC,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ParseableParametrized<NlaBuffer<&'a T>, u16> for Nla {
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        interface_family: u16,
    ) -> Result<Self, DecodeError> {
        use Nla::*;
        let payload = buf.value();
        Ok(match buf.kind() {
            // Vec<u8>
            IFLA_UNSPEC => Unspec(ByteVec::from(payload)),
            IFLA_COST => Cost(ByteVec::from(payload)),
            IFLA_PRIORITY => Priority(ByteVec::from(payload)),
            IFLA_WEIGHT => Weight(ByteVec::from(payload)),
            IFLA_VFINFO_LIST => VfInfoList(ByteVec::from(payload)),
            IFLA_VF_PORTS => VfPorts(ByteVec::from(payload)),
            IFLA_PORT_SELF => PortSelf(ByteVec::from(payload)),
            IFLA_PHYS_PORT_ID => PhysPortId(ByteVec::from(payload)),
            IFLA_PHYS_SWITCH_ID => PhysSwitchId(ByteVec::from(payload)),
            IFLA_WIRELESS => Wireless(ByteVec::from(payload)),
            IFLA_PROTINFO => ProtoInfo(ByteVec::from(payload)),
            IFLA_PAD => Pad(ByteVec::from(payload)),
            IFLA_XDP => Xdp(ByteVec::from(payload)),
            IFLA_EVENT => Event(ByteVec::from(payload)),
            IFLA_NEW_NETNSID => NewNetnsId(ByteVec::from(payload)),
            IFLA_IF_NETNSID => IfNetnsId(ByteVec::from(payload)),
            IFLA_CARRIER_UP_COUNT => CarrierUpCount(ByteVec::from(payload)),
            IFLA_CARRIER_DOWN_COUNT => CarrierDownCount(ByteVec::from(payload)),
            IFLA_NEW_IFINDEX => NewIfIndex(ByteVec::from(payload)),
            IFLA_PROP_LIST => PropList(ByteVec::from(payload)),
            IFLA_PROTO_DOWN_REASON => ProtoDownReason(ByteVec::from(payload)),
            // HW address (we parse them as Vec for now, because for IP over GRE, the HW address is
            // an IP instead of a MAC for example
            IFLA_ADDRESS => Address(ByteVec::from(payload)),
            IFLA_BROADCAST => Broadcast(ByteVec::from(payload)),
            IFLA_PERM_ADDRESS => PermAddress(ByteVec::from(payload)),
            // String
            IFLA_IFNAME => IfName(parse_string(payload).context("invalid IFLA_IFNAME value")?),
            IFLA_QDISC => Qdisc(parse_string(payload).context("invalid IFLA_QDISC value")?),
            IFLA_IFALIAS => IfAlias(parse_string(payload).context("invalid IFLA_IFALIAS value")?),
            IFLA_PHYS_PORT_NAME => {
                PhysPortName(parse_string(payload).context("invalid IFLA_PHYS_PORT_NAME value")?)
            }
            IFLA_ALT_IFNAME => {
                AltIfName(parse_string(payload).context("invalid IFLA_ALT_IFNAME value")?)
            }

            // u8
            IFLA_LINKMODE => Mode(parse_u8(payload).context("invalid IFLA_LINKMODE value")?),
            IFLA_CARRIER => Carrier(parse_u8(payload).context("invalid IFLA_CARRIER value")?),
            IFLA_PROTO_DOWN => {
                ProtoDown(parse_u8(payload).context("invalid IFLA_PROTO_DOWN value")?)
            }

            IFLA_MTU => Mtu(parse_u32(payload).context("invalid IFLA_MTU value")?),
            IFLA_LINK => Link(parse_u32(payload).context("invalid IFLA_LINK value")?),
            IFLA_MASTER => Master(parse_u32(payload).context("invalid IFLA_MASTER value")?),
            IFLA_TXQLEN => TxQueueLen(parse_u32(payload).context("invalid IFLA_TXQLEN value")?),
            IFLA_NET_NS_PID => {
                NetNsPid(parse_u32(payload).context("invalid IFLA_NET_NS_PID value")?)
            }
            IFLA_NUM_VF => NumVf(parse_u32(payload).context("invalid IFLA_NUM_VF value")?),
            IFLA_GROUP => Group(parse_u32(payload).context("invalid IFLA_GROUP value")?),
            IFLA_NET_NS_FD => NetNsFd(parse_i32(payload).context("invalid IFLA_NET_NS_FD value")?),
            IFLA_EXT_MASK => ExtMask(parse_u32(payload).context("invalid IFLA_EXT_MASK value")?),
            IFLA_PROMISCUITY => {
                Promiscuity(parse_u32(payload).context("invalid IFLA_PROMISCUITY value")?)
            }
            IFLA_NUM_TX_QUEUES => {
                NumTxQueues(parse_u32(payload).context("invalid IFLA_NUM_TX_QUEUES value")?)
            }
            IFLA_NUM_RX_QUEUES => {
                NumRxQueues(parse_u32(payload).context("invalid IFLA_NUM_RX_QUEUES value")?)
            }
            IFLA_CARRIER_CHANGES => {
                CarrierChanges(parse_u32(payload).context("invalid IFLA_CARRIER_CHANGES value")?)
            }
            IFLA_GSO_MAX_SEGS => {
                GsoMaxSegs(parse_u32(payload).context("invalid IFLA_GSO_MAX_SEGS value")?)
            }
            IFLA_GSO_MAX_SIZE => {
                GsoMaxSize(parse_u32(payload).context("invalid IFLA_GSO_MAX_SIZE value")?)
            }
            IFLA_MIN_MTU => MinMtu(parse_u32(payload).context("invalid IFLA_MIN_MTU value")?),
            IFLA_MAX_MTU => MaxMtu(parse_u32(payload).context("invalid IFLA_MAX_MTU value")?),
            IFLA_LINK_NETNSID => {
                NetnsId(parse_i32(payload).context("invalid IFLA_LINK_NETNSID value")?)
            }
            IFLA_OPERSTATE => OperState(
                parse_u8(payload)
                    .context("invalid IFLA_OPERSTATE value")?
                    .into(),
            ),
            IFLA_MAP => Map(ByteVec::from(payload)),
            IFLA_STATS => Stats(ByteVec::from(payload)),
            IFLA_STATS64 => Stats64(ByteVec::from(payload)),
            IFLA_AF_SPEC => match interface_family as u16 {
                AF_INET | AF_INET6 | AF_UNSPEC => {
                    let mut nlas = vec![];
                    let err = "invalid IFLA_AF_SPEC value";
                    for nla in NlasIterator::new(payload) {
                        let nla = nla.context(err)?;
                        nlas.push(af_spec_inet::AfSpecInet::parse(&nla).context(err)?);
                    }
                    AfSpecInet(nlas)
                }
                AF_BRIDGE => AfSpecBridge(ByteVec::from(payload)),
                _ => AfSpecUnknown(ByteVec::from(payload)),
            },
            IFLA_LINKINFO => {
                let err = "invalid IFLA_LINKINFO value";
                let buf = NlaBuffer::new_checked(payload).context(err)?;
                Info(VecInfo::parse(&buf).context(err)?.0)
            }

            kind => Other(DefaultNla::parse(buf).context(format!("unknown NLA type {}", kind))?),
        })
    }
}
