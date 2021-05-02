mod cache_info;
pub use self::cache_info::*;

mod metrics;
pub use self::metrics::*;

mod mfc_stats;
pub use self::mfc_stats::*;

mod next_hops;
pub use self::next_hops::*;

use anyhow::Context;
use byteorder::{ByteOrder, NativeEndian};

use crate::{
    constants::*,
    nlas::{self, DefaultNla, NlaBuffer},
    parsers::{parse_u16, parse_u32},
    traits::Parseable,
    ByteVec,
    DecodeError,
};

#[cfg(feature = "rich_nlas")]
use crate::traits::Emitable;

/// Netlink attributes for `RTM_NEWROUTE`, `RTM_DELROUTE`,
/// `RTM_GETROUTE` messages.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Nla {
    #[cfg(not(feature = "rich_nlas"))]
    Metrics(ByteVec),
    #[cfg(feature = "rich_nlas")]
    Metrics(Metrics),
    #[cfg(not(feature = "rich_nlas"))]
    MfcStats(ByteVec),
    #[cfg(feature = "rich_nlas")]
    MfcStats(MfcStats),
    #[cfg(not(feature = "rich_nlas"))]
    MultiPath(ByteVec),
    #[cfg(feature = "rich_nlas")]
    MultiPath(NextHops),
    #[cfg(not(feature = "rich_nlas"))]
    CacheInfo(ByteVec),
    #[cfg(feature = "rich_nlas")]
    CacheInfo(CacheInfo),
    Unspec(ByteVec),
    Destination(ByteVec),
    Source(ByteVec),
    Gateway(ByteVec),
    PrefSource(ByteVec),
    Session(ByteVec),
    MpAlgo(ByteVec),
    Via(ByteVec),
    NewDestination(ByteVec),
    Pref(ByteVec),
    Encap(ByteVec),
    Expires(ByteVec),
    Pad(ByteVec),
    Uid(ByteVec),
    TtlPropagate(ByteVec),
    EncapType(u16),
    Iif(u32),
    Oif(u32),
    Priority(u32),
    ProtocolInfo(u32),
    Flow(u32),
    Table(u32),
    Mark(u32),
    Other(DefaultNla),
}

impl nlas::Nla for Nla {
    #[rustfmt::skip]
    fn value_len(&self) -> usize {
        use self::Nla::*;
        match *self {
            Unspec(ref bytes)
                | Destination(ref bytes)
                | Source(ref bytes)
                | Gateway(ref bytes)
                | PrefSource(ref bytes)
                | Session(ref bytes)
                | MpAlgo(ref bytes)
                | Via(ref bytes)
                | NewDestination(ref bytes)
                | Pref(ref bytes)
                | Encap(ref bytes)
                | Expires(ref bytes)
                | Pad(ref bytes)
                | Uid(ref bytes)
                | TtlPropagate(ref bytes)
                => bytes.len(),

            #[cfg(not(feature = "rich_nlas"))]
            CacheInfo(ref bytes)
                | MfcStats(ref bytes)
                | Metrics(ref bytes)
                | MultiPath(ref bytes)
                => bytes.len(),

            #[cfg(feature = "rich_nlas")]
            CacheInfo(ref cache_info) => cache_info.buffer_len(),
            #[cfg(feature = "rich_nlas")]
            MfcStats(ref stats) => stats.buffer_len(),
            #[cfg(feature = "rich_nlas")]
            Metrics(ref metrics) => metrics.buffer_len(),
            #[cfg(feature = "rich_nlas")]
            MultiPath(ref next_hops) => next_hops.buffer_len(),

            EncapType(_) => 2,
            Iif(_)
                | Oif(_)
                | Priority(_)
                | ProtocolInfo(_)
                | Flow(_)
                | Table(_)
                | Mark(_)
                => 4,

            Other(ref attr) => attr.value_len(),
        }
    }

    #[rustfmt::skip]
    fn emit_value(&self, buffer: &mut [u8]) {
        use self::Nla::*;
        match *self {
            Unspec(ref bytes)
                | Destination(ref bytes)
                | Source(ref bytes)
                | Gateway(ref bytes)
                | PrefSource(ref bytes)
                | Session(ref bytes)
                | MpAlgo(ref bytes)
                | Via(ref bytes)
                | NewDestination(ref bytes)
                | Pref(ref bytes)
                | Encap(ref bytes)
                | Expires(ref bytes)
                | Pad(ref bytes)
                | Uid(ref bytes)
                | TtlPropagate(ref bytes)
                => buffer.copy_from_slice(bytes.as_slice()),

            #[cfg(not(feature = "rich_nlas"))]
                MultiPath(ref bytes)
                | CacheInfo(ref bytes)
                | MfcStats(ref bytes)
                | Metrics(ref bytes)
                => buffer.copy_from_slice(bytes.as_slice()),

            #[cfg(feature = "rich_nlas")]
            CacheInfo(ref cache_info) => cache_info.emit(buffer),
            #[cfg(feature = "rich_nlas")]
            MfcStats(ref stats) => stats.emit(buffer),
            #[cfg(feature = "rich_nlas")]
            Metrics(ref metrics) => metrics.emit(buffer),
            #[cfg(feature = "rich_nlas")]
            MultiPath(ref next_hops) => next_hops.emit(buffer),

            EncapType(value) => NativeEndian::write_u16(buffer, value),
            Iif(value)
                | Oif(value)
                | Priority(value)
                | ProtocolInfo(value)
                | Flow(value)
                | Table(value)
                | Mark(value)
                => NativeEndian::write_u32(buffer, value),
            Other(ref attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        use self::Nla::*;
        match *self {
            Unspec(_) => RTA_UNSPEC,
            Destination(_) => RTA_DST,
            Source(_) => RTA_SRC,
            Iif(_) => RTA_IIF,
            Oif(_) => RTA_OIF,
            Gateway(_) => RTA_GATEWAY,
            Priority(_) => RTA_PRIORITY,
            PrefSource(_) => RTA_PREFSRC,
            Metrics(_) => RTA_METRICS,
            MultiPath(_) => RTA_MULTIPATH,
            ProtocolInfo(_) => RTA_PROTOINFO,
            Flow(_) => RTA_FLOW,
            CacheInfo(_) => RTA_CACHEINFO,
            Session(_) => RTA_SESSION,
            MpAlgo(_) => RTA_MP_ALGO,
            Table(_) => RTA_TABLE,
            Mark(_) => RTA_MARK,
            MfcStats(_) => RTA_MFC_STATS,
            Via(_) => RTA_VIA,
            NewDestination(_) => RTA_NEWDST,
            Pref(_) => RTA_PREF,
            EncapType(_) => RTA_ENCAP_TYPE,
            Encap(_) => RTA_ENCAP,
            Expires(_) => RTA_EXPIRES,
            Pad(_) => RTA_PAD,
            Uid(_) => RTA_UID,
            TtlPropagate(_) => RTA_TTL_PROPAGATE,
            Other(ref attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for Nla {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        use self::Nla::*;

        let payload = buf.value();
        Ok(match buf.kind() {
            RTA_UNSPEC => Unspec(ByteVec::from(payload)),
            RTA_DST => Destination(ByteVec::from(payload)),
            RTA_SRC => Source(ByteVec::from(payload)),
            RTA_GATEWAY => Gateway(ByteVec::from(payload)),
            RTA_PREFSRC => PrefSource(ByteVec::from(payload)),
            RTA_SESSION => Session(ByteVec::from(payload)),
            RTA_MP_ALGO => MpAlgo(ByteVec::from(payload)),
            RTA_VIA => Via(ByteVec::from(payload)),
            RTA_NEWDST => NewDestination(ByteVec::from(payload)),
            RTA_PREF => Pref(ByteVec::from(payload)),
            RTA_ENCAP => Encap(ByteVec::from(payload)),
            RTA_EXPIRES => Expires(ByteVec::from(payload)),
            RTA_PAD => Pad(ByteVec::from(payload)),
            RTA_UID => Uid(ByteVec::from(payload)),
            RTA_TTL_PROPAGATE => TtlPropagate(ByteVec::from(payload)),
            RTA_ENCAP_TYPE => {
                EncapType(parse_u16(payload).context("invalid RTA_ENCAP_TYPE value")?)
            }
            RTA_IIF => Iif(parse_u32(payload).context("invalid RTA_IIF value")?),
            RTA_OIF => Oif(parse_u32(payload).context("invalid RTA_OIF value")?),
            RTA_PRIORITY => Priority(parse_u32(payload).context("invalid RTA_PRIORITY value")?),
            RTA_PROTOINFO => {
                ProtocolInfo(parse_u32(payload).context("invalid RTA_PROTOINFO value")?)
            }
            RTA_FLOW => Flow(parse_u32(payload).context("invalid RTA_FLOW value")?),
            RTA_TABLE => Table(parse_u32(payload).context("invalid RTA_TABLE value")?),
            RTA_MARK => Mark(parse_u32(payload).context("invalid RTA_MARK value")?),

            #[cfg(not(feature = "rich_nlas"))]
            RTA_CACHEINFO => CacheInfo(ByteVec::from(payload)),
            #[cfg(feature = "rich_nlas")]
            RTA_CACHEINFO => CacheInfo(
                cache_info::CacheInfo::parse(
                    &CacheInfoBuffer::new_checked(payload)
                        .context("invalid RTA_CACHEINFO value")?,
                )
                .context("invalid RTA_CACHEINFO value")?,
            ),
            #[cfg(not(feature = "rich_nlas"))]
            RTA_MFC_STATS => MfcStats(ByteVec::from(payload)),
            #[cfg(feature = "rich_nlas")]
            RTA_MFC_STATS => MfcStats(
                mfc_stats::MfcStats::parse(
                    &MfcStatsBuffer::new_checked(payload).context("invalid RTA_MFC_STATS value")?,
                )
                .context("invalid RTA_MFC_STATS value")?,
            ),
            #[cfg(not(feature = "rich_nlas"))]
            RTA_METRICS => Metrics(ByteVec::from(payload)),
            #[cfg(feature = "rich_nlas")]
            RTA_METRICS => Metrics(
                metrics::Metrics::parse(
                    &NlaBuffer::new_checked(payload).context("invalid RTA_METRICS value")?,
                )
                .context("invalid RTA_METRICS value")?,
            ),
            #[cfg(not(feature = "rich_nlas"))]
            RTA_MULTIPATH => MultiPath(ByteVec::from(payload)),
            #[cfg(feature = "rich_nlas")]
            RTA_MULTIPATH => MultiPath(
                NextHops::parse(
                    &NextHopsBuffer::new_checked(payload).context("invalid RTA_MULTIPATH value")?,
                )
                .context("invalid RTA_MULTIPATH value")?,
            ),
            _ => Other(DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?),
        })
    }
}
