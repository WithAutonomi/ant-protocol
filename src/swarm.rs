//! Swarm messages: clients downloading the same file find each other through
//! the nodes closest to it, and then share its records directly.
//!
//! Every client reading a file asks the same close group for the same
//! records. Records are content addressed and every client checks each one
//! against its address, so a record from another client is as good as one
//! from a node. Clients therefore form a swarm per file (a *room*), the way
//! `BitTorrent` peers do, and the nodes play two parts in it:
//!
//! - **the introducer**: a client announces itself in a room at the nodes
//!   closest to the room's key ([`SWARM_RENDEZVOUS_NODES`] of them) and hands
//!   them WebRTC offers; each node passes every offer to another member of the
//!   room and carries that member's answer back. After that the two clients
//!   talk over their own WebRTC connection and the node is out of the way;
//! - **the last seed**: a record no other client has is fetched from the
//!   nodes, as it always was.
//!
//! The node needs no new connection to a client: requests and replies travel
//! on the connection the client already uses for chunk GETs. Signals for a
//! client wait in a small inbox at the node until the client's next announce,
//! which may also wait for them (a long poll of at most
//! [`MAX_SWARM_WAIT_MS`]).
//!
//! The node assigns each member its [`MemberId`] from the authenticated
//! connection, so a client cannot speak for another; and an answer is passed
//! on only for an offer the node delivered to the answering member.
//!
//! The node is also the STUN server for those WebRTC connections: its reply
//! names its STUN address, which tells a client the public address other
//! clients can reach it at, without any third-party server.
//!
//! The rendezvous nodes are picked by closeness to the room's key alone; they
//! need not hold any of the file's records, which are fetched from their own
//! close groups as always.
//!
//! The record exchange between two clients is the clients' business and is
//! not part of this protocol.
//!
//! Every enum here is encoded by its variant's position: variants may only be
//! appended, never reordered or removed (the tests pin each one).

use std::fmt;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr};

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::chunk::{ProtocolError, XorName};

/// How many of the nodes closest to a room's key a client announces at.
/// Two clients whose views of the close group differ slightly still share at
/// least one of them.
pub const SWARM_RENDEZVOUS_NODES: usize = 2;

/// The most offers one announce may carry.
pub const MAX_SWARM_OFFERS: usize = 8;

/// The largest SDP an offer or an answer may carry, in bytes. A non-trickle
/// WebRTC offer with a data channel and a few candidates is 1 to 3 KiB.
pub const MAX_SWARM_SDP_BYTES: usize = 16 * 1024;

/// The most signals one reply may carry.
pub const MAX_SWARM_INBOX: usize = 32;

/// The most SDP bytes one reply carries in all; signals past it wait for the
/// next announce. Keeps a reply well inside the browser transport's 64 KiB
/// limit for small responses.
pub const MAX_SWARM_REPLY_SDP_BYTES: usize = 48 * 1024;

/// The longest an announce may wait for a signal before the node replies.
pub const MAX_SWARM_WAIT_MS: u32 = 20_000;

/// The most STUN servers one reply names.
pub const MAX_SWARM_ICE_SERVERS: usize = 4;

/// The longest STUN server URL a reply may carry, in bytes.
pub const MAX_SWARM_ICE_SERVER_BYTES: usize = 256;

/// The largest encoded swarm request, in bytes: an announce with every offer
/// at its largest, with room to spare for ids and framing. A node can refuse a
/// longer message from its length alone, before decoding it.
pub const MAX_SWARM_REQUEST_BYTES: usize = MAX_SWARM_OFFERS * (MAX_SWARM_SDP_BYTES + 64) + 256;

/// How long a node keeps an offer it delivered waiting for its answer, and a
/// signal waiting for its member's next announce. It covers the slowest
/// answer a client gives (the announce that collects the offer, the WebRTC
/// negotiation and the answer's own request), which each client checks its
/// own bounds against; an offering client keeps its offer longer still.
pub const SWARM_SIGNAL_TTL_MS: u64 = 70_000;

/// The longest error text a swarm reply carries, in bytes. A reply with a
/// longer one fails its check whole.
pub const MAX_SWARM_ERROR_BYTES: usize = 512;

/// The most ICE candidates one swarm SDP keeps (see [`constrain_swarm_sdp`]).
pub const MAX_SWARM_CANDIDATES: usize = 16;

/// A room member, as the node that hosts the room names it.
pub type MemberId = [u8; 16];

/// An offer, as the client that made it names it.
pub type OfferId = [u8; 16];

/// A rendezvous node, by its peer id.
///
/// Every swarm request names the node it is for, and a node refuses one that
/// names another: a native client's request is signed but not bound to the
/// connection it travels on, so without this a node that saw it could send it
/// again, in the client's name, to the room's other rendezvous node.
pub type NodeId = [u8; 32];

/// One of a client's memberships of a room: a number that grows each time
/// the client joins the room anew. A node compares only the numbers of one
/// connection identity (a native client's peer id, which a client makes
/// afresh each time it starts, or one browser connection), so they need grow
/// only for as long as that identity lives.
///
/// A node keeps each connection's newest membership of a room: an announce
/// naming a newer one starts a member in place of the old, and a leave ends
/// the membership it names (or an older one in its place). An announce naming
/// a membership the client ended (left, or replaced by a newer one), or an
/// older one, is refused for as long as a node accepts a request sent before
/// it ended; so a request of a membership the client has left, however late
/// it arrives, cannot end or take over a newer one, nor bring the old one
/// back. A node remembers a bounded number of ended memberships (per
/// connection, per host and in all, the oldest forgotten first); one it has
/// forgotten can come back only as a member that is dropped once silent. A
/// membership dropped because its connection closed or it went silent is not
/// ended: the client carries on in it over a new connection.
pub type Membership = u64;

/// The room for a file: the key every client downloading it derives the same
/// way. For a public file this is its address (that of its `DataMap`); a
/// client that only has a `DataMap` derives it from the `DataMap`'s content.
pub type RoomKey = XorName;

/// A WebRTC offer for whichever member the node picks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmOffer {
    /// Names the offer in the answer that comes back.
    pub offer_id: OfferId,
    /// The offer's session description, with its ICE candidates.
    pub sdp: String,
}

/// A message for one member, carried by the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SwarmSignal {
    /// Another member's offer: answer it with a [`SwarmAnswerRequest`].
    Offer {
        /// The member that made the offer.
        from: MemberId,
        /// The offer's id, to quote in the answer.
        offer_id: OfferId,
        /// The offer's session description.
        sdp: String,
    },
    /// The answer to one of this member's offers.
    Answer {
        /// The member that answered.
        from: MemberId,
        /// Which offer it answers.
        offer_id: OfferId,
        /// The answer's session description.
        sdp: String,
    },
}

/// Join or stay in a room, hand over offers, and collect signals.
///
/// The first announce in a room joins it; later ones keep the membership
/// alive (a member that stops announcing is dropped). Each offer goes to a
/// different member, picked by the node. If there is nothing for this member
/// yet, the node may hold the reply for up to `wait_ms` (at most
/// [`MAX_SWARM_WAIT_MS`]) and send it as soon as a signal arrives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmAnnounceRequest {
    /// The room.
    pub room: RoomKey,
    /// The node this announce is for.
    pub node: NodeId,
    /// The membership this announce is for.
    pub membership: Membership,
    /// Offers for other members, at most [`MAX_SWARM_OFFERS`].
    #[serde(deserialize_with = "offers")]
    pub offers: Vec<SwarmOffer>,
    /// How long the node may wait for a signal, in milliseconds.
    pub wait_ms: u32,
}

/// The reply to an announce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SwarmAnnounceResponse {
    /// In the room.
    Joined {
        /// This member's id in the room, as other members see it.
        member: MemberId,
        /// Members in the room, this one included.
        members: u32,
        /// How many of the offers were handed to a member: always the first
        /// ones, in order; the rest reached no one.
        offers_delivered: u32,
        /// Signals for this member, oldest first, at most [`MAX_SWARM_INBOX`].
        #[serde(deserialize_with = "inbox")]
        inbox: Vec<SwarmSignal>,
        /// STUN servers this node runs, as `RTCIceServer` URLs
        /// (`stun:203.0.113.5:10000`), for the client's WebRTC connections to
        /// other members. The node answers only clients that announced in a
        /// room recently. Empty when the node has no public address.
        #[serde(deserialize_with = "ice_servers")]
        ice_servers: Vec<String>,
    },
    /// Not admitted; the client fetches from nodes alone.
    Refused(SwarmRefusal),
    /// The request was malformed.
    Error(ProtocolError),
}

/// Why a node did not admit an announce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SwarmRefusal {
    /// The room has as many members as the node keeps.
    RoomFull,
    /// The node hosts as many rooms as it keeps.
    TooManyRooms,
    /// This connection is in as many rooms as the node allows.
    TooManyRoomsForPeer,
    /// The node is shedding swarm work; try again later.
    Busy,
    /// The announce names a membership the client has ended or replaced, or
    /// one older than that.
    Superseded,
    /// The node hosts no rooms: browsers cannot reach it (it has no WebRTC
    /// Direct endpoint), so readers of every kind could not all meet there.
    /// A client passes it over at once.
    NotHosting,
}

/// Answer an offer the node delivered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmAnswerRequest {
    /// The room the offer came through.
    pub room: RoomKey,
    /// The node this answer is for: the one that delivered the offer.
    pub node: NodeId,
    /// The member that made the offer.
    pub to: MemberId,
    /// The offer being answered.
    pub offer_id: OfferId,
    /// The answer's session description.
    pub sdp: String,
}

/// The reply to an answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SwarmAnswerResponse {
    /// Queued for the member that made the offer.
    Delivered,
    /// No such offer was delivered to this member, it expired, or it was
    /// already answered.
    Unmatched,
    /// The request was malformed.
    Error(ProtocolError),
}

/// Leave a room.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmLeaveRequest {
    /// The room.
    pub room: RoomKey,
    /// The node this leave is for.
    pub node: NodeId,
    /// The membership that leaves (an older one in its place goes too; a
    /// newer one stays).
    pub membership: Membership,
}

/// The reply to a leave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SwarmLeaveResponse {
    /// No longer a member (or never was).
    Left,
    /// The request was malformed, or names another node.
    Error(ProtocolError),
}

impl SwarmAnnounceRequest {
    /// Checks the limits both sides agree on.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Internal`] naming the first limit exceeded.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.offers.len() > MAX_SWARM_OFFERS {
            return Err(ProtocolError::Internal(format!(
                "a swarm announce carries at most {MAX_SWARM_OFFERS} offers"
            )));
        }
        if self
            .offers
            .iter()
            .any(|offer| offer.sdp.len() > MAX_SWARM_SDP_BYTES)
        {
            return Err(sdp_too_large());
        }
        if self.wait_ms > MAX_SWARM_WAIT_MS {
            return Err(ProtocolError::Internal(format!(
                "a swarm announce waits at most {MAX_SWARM_WAIT_MS} ms"
            )));
        }
        Ok(())
    }
}

impl SwarmAnnounceResponse {
    /// Checks the limits both sides agree on. A client checks a reply before
    /// acting on it.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Internal`] naming the first limit exceeded.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        let Self::Joined {
            inbox,
            ice_servers,
            offers_delivered,
            ..
        } = self
        else {
            return match self {
                Self::Error(error) => error_fits(error),
                _ => Ok(()),
            };
        };
        // No announce carries more; a client also checks the count against
        // the offers it sent.
        if usize::try_from(*offers_delivered).map_or(true, |delivered| delivered > MAX_SWARM_OFFERS)
        {
            return Err(ProtocolError::Internal(format!(
                "a swarm reply counts at most {MAX_SWARM_OFFERS} offers delivered"
            )));
        }
        if inbox.len() > MAX_SWARM_INBOX {
            return Err(ProtocolError::Internal(format!(
                "a swarm reply carries at most {MAX_SWARM_INBOX} signals"
            )));
        }
        if inbox
            .iter()
            .any(|signal| signal.sdp().len() > MAX_SWARM_SDP_BYTES)
        {
            return Err(sdp_too_large());
        }
        let total: usize = inbox.iter().map(|signal| signal.sdp().len()).sum();
        if total > MAX_SWARM_REPLY_SDP_BYTES {
            return Err(ProtocolError::Internal(format!(
                "a swarm reply carries at most {MAX_SWARM_REPLY_SDP_BYTES} bytes of SDP"
            )));
        }
        if ice_servers.len() > MAX_SWARM_ICE_SERVERS
            || ice_servers
                .iter()
                .any(|server| server.len() > MAX_SWARM_ICE_SERVER_BYTES)
        {
            return Err(ProtocolError::Internal(format!(
                "a swarm reply names at most {MAX_SWARM_ICE_SERVERS} STUN servers of at most \
                 {MAX_SWARM_ICE_SERVER_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

impl SwarmSignal {
    /// The signal's session description.
    #[must_use]
    pub fn sdp(&self) -> &str {
        match self {
            Self::Offer { sdp, .. } | Self::Answer { sdp, .. } => sdp,
        }
    }
}

impl SwarmAnswerRequest {
    /// Checks the limits both sides agree on.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Internal`] if the SDP is too large.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.sdp.len() > MAX_SWARM_SDP_BYTES {
            return Err(sdp_too_large());
        }
        Ok(())
    }
}

impl SwarmAnswerResponse {
    /// Checks the limits both sides agree on. A client checks a reply before
    /// acting on it.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Internal`] if the reply's error is too long.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Error(error) => error_fits(error),
            Self::Delivered | Self::Unmatched => Ok(()),
        }
    }
}

impl SwarmLeaveResponse {
    /// Checks the limits both sides agree on. A client checks a reply before
    /// acting on it.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::Internal`] if the reply's error is too long.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Error(error) => error_fits(error),
            Self::Left => Ok(()),
        }
    }
}

/// Decodes a sequence of at most `max` elements, and refuses a longer one
/// before decoding an element past the limit: a message cannot make its
/// receiver build more of a list than `validate` would then let through.
fn bounded_vec<'de, D, T>(deserializer: D, max: usize) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T> {
        max: usize,
        element: PhantomData<T>,
    }

    impl<'de, T: Deserialize<'de>> Visitor<'de> for Bounded<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a sequence of at most {} elements", self.max)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            if let Some(len) = seq.size_hint().filter(|len| *len > self.max) {
                return Err(de::Error::invalid_length(len, &self));
            }
            let mut elements = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(self.max));
            while let Some(element) = seq.next_element()? {
                if elements.len() >= self.max {
                    return Err(de::Error::invalid_length(elements.len() + 1, &self));
                }
                elements.push(element);
            }
            Ok(elements)
        }
    }

    deserializer.deserialize_seq(Bounded {
        max,
        element: PhantomData,
    })
}

fn offers<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<SwarmOffer>, D::Error> {
    bounded_vec(deserializer, MAX_SWARM_OFFERS)
}

fn inbox<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<SwarmSignal>, D::Error> {
    bounded_vec(deserializer, MAX_SWARM_INBOX)
}

fn ice_servers<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    bounded_vec(deserializer, MAX_SWARM_ICE_SERVERS)
}

fn sdp_too_large() -> ProtocolError {
    ProtocolError::Internal(format!(
        "a swarm SDP is at most {MAX_SWARM_SDP_BYTES} bytes"
    ))
}

fn error_fits(error: &ProtocolError) -> Result<(), ProtocolError> {
    if error.to_string().len() > MAX_SWARM_ERROR_BYTES {
        return Err(ProtocolError::Internal(format!(
            "a swarm reply's error is at most {MAX_SWARM_ERROR_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Rewrites a swarm SDP to the ICE candidates its receiver may be asked to
/// try: UDP candidates on a port, naming either an IP address that is not
/// unspecified, multicast or broadcast, or a multicast DNS (`.local`) name,
/// that `keep` accepts (given the IP, or `None` for a name). At most
/// [`MAX_SWARM_CANDIDATES`] are kept, in order. The result holds no more
/// memory than its length needs.
///
/// An offer or answer comes from another client, which picks its
/// candidates, and its receiver sends connectivity checks to each of them
/// before anything proves who made it. A node relaying an SDP and a client
/// applying one both pass it through here, so neither turns readers into a
/// way to send traffic wherever a stranger points them.
///
/// Receivers read SDP leniently: webrtc-rs trims an attribute's value and
/// skips a carriage return before a line, Chrome takes an attribute name
/// followed by a space, Firefox's parser names attributes in any case. So
/// that what a receiver reads is exactly what was checked, a line any of
/// them may read as a candidate or a DTLS fingerprint stays only in its one
/// standard form (`a=candidate:` or `a=fingerprint:`, then printable ASCII
/// words separated by single spaces, which every parser splits into the same
/// fields), and a line with a carriage return anywhere but
/// before its line feed is dropped. A link's binding, which covers the
/// standard fingerprint lines, so covers every fingerprint a receiver uses.
/// Every other line stays as it was.
#[must_use]
pub fn constrain_swarm_sdp(sdp: &str, keep: impl Fn(Option<IpAddr>) -> bool) -> String {
    let mut kept = 0usize;
    let mut out = String::with_capacity(sdp.len());
    for line in sdp.split_inclusive('\n') {
        let text = line.strip_suffix('\n').unwrap_or(line);
        let text = text.strip_suffix('\r').unwrap_or(text);
        if text.contains('\r') {
            continue;
        }
        match attribute_name(text) {
            Some(name) if name.eq_ignore_ascii_case("candidate") => {
                let Some(candidate) = standard_value(text, "a=candidate:") else {
                    continue;
                };
                if kept >= MAX_SWARM_CANDIDATES || !candidate_allowed(candidate, &keep) {
                    continue;
                }
                kept += 1;
            }
            Some(name)
                if name.eq_ignore_ascii_case("fingerprint")
                    && standard_value(text, "a=fingerprint:").is_none() =>
            {
                continue;
            }
            _ => {}
        }
        out.push_str(line);
    }
    // Built for the whole input: one that was mostly dropped candidates
    // must not keep holding the input's size.
    out.shrink_to_fit();
    out
}

/// The name of the attribute an SDP line may be read as, as leniently as
/// any receiver reads one: `a=` (in either case, with whitespace anywhere
/// around it), then the name, up to a colon or whitespace.
fn attribute_name(line: &str) -> Option<&str> {
    let value = line
        .trim_start()
        .strip_prefix(['a', 'A'])?
        .trim_start()
        .strip_prefix('=')?
        .trim_start();
    value.split(|c: char| c == ':' || c.is_whitespace()).next()
}

/// The value of `line` if it is the standard form of the attribute `prefix`
/// starts: `prefix`, then printable ASCII words separated by single spaces.
/// Parsers split a value on different whitespace (webrtc-ice on any Unicode
/// whitespace, others on spaces alone), so only a value they all split into
/// the same fields is kept.
fn standard_value<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    line.strip_prefix(prefix).filter(|value| {
        value.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
            && value.split(' ').all(|word| !word.is_empty())
    })
}

/// Whether one candidate (`a=candidate:` taken off) may be kept.
fn candidate_allowed(candidate: &str, keep: &impl Fn(Option<IpAddr>) -> bool) -> bool {
    // foundation component transport priority address port "typ" type ...
    let mut fields = candidate.split_ascii_whitespace();
    let (
        Some(_),
        Some(component),
        Some(transport),
        Some(priority),
        Some(address),
        Some(port),
        Some("typ"),
        Some(_),
    ) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    )
    else {
        return false;
    };
    if !transport.eq_ignore_ascii_case("udp") || port.parse::<u16>().map_or(true, |port| port == 0)
    {
        return false;
    }
    // Components are numbered 1 to 256 (RFC 8445): a receiver's ICE agent
    // works a priority of 0 out from its component, which a larger one would
    // overflow.
    if !component
        .parse::<u16>()
        .is_ok_and(|component| (1..=256).contains(&component))
        || priority.parse::<u32>().is_err()
    {
        return false;
    }
    match address.parse::<IpAddr>() {
        Ok(ip) => {
            let ip = canonical_ip(ip);
            !ip.is_unspecified()
                && !ip.is_multicast()
                && ip != IpAddr::V4(Ipv4Addr::BROADCAST)
                && keep(Some(ip))
        }
        Err(_) => is_mdns_name(address) && keep(None),
    }
}

/// A browser's obfuscated host candidate: a multicast DNS name, which only
/// resolves on the reader's own network.
fn is_mdns_name(name: &str) -> bool {
    name.len() <= 255
        && name.strip_suffix(".local").is_some_and(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        })
}

/// `ip`, with an IPv4-mapped IPv6 address as the IPv4 address it maps.
#[must_use]
pub fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// Whether `ip` is reachable across the internet, as the IANA special-purpose
/// address registries have it: no address of "this network", private use,
/// shared (carrier-grade NAT), loopback, link-local, IETF protocol
/// assignments, documentation, benchmarking, multicast, reserved or
/// broadcast for IPv4; for IPv6, only global unicast (`2000::/3`) outside
/// the IETF protocol assignments (`2001::/23`) and documentation
/// (`2001:db8::/32`, `3fff::/20`). An IPv4-mapped IPv6 address is judged as
/// IPv4.
#[must_use]
pub fn is_global_ip(ip: IpAddr) -> bool {
    match canonical_ip(ip) {
        IpAddr::V4(v4) => {
            let [first, second, third, _] = v4.octets();
            !(first == 0
                || first == 10
                || (first == 100 && (64..128).contains(&second))
                || first == 127
                || (first == 169 && second == 254)
                || (first == 172 && (16..32).contains(&second))
                || (first == 192 && second == 0 && third == 0)
                || (first == 192 && second == 0 && third == 2)
                || (first == 192 && second == 88 && third == 99)
                || (first == 192 && second == 168)
                || (first == 198 && (18..20).contains(&second))
                || (first == 198 && second == 51 && third == 100)
                || (first == 203 && second == 0 && third == 113)
                || first >= 224)
        }
        IpAddr::V6(v6) => {
            let [first, second, ..] = v6.segments();
            first & 0xe000 == 0x2000
                && !(first == 0x2001 && second < 0x0200)
                && !(first == 0x2001 && second == 0x0db8)
                && !(first == 0x3fff && second & 0xf000 == 0)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// An SDP with one candidate of every kind a sender could put in it.
    const SDP: &str = "v=0\r\n\
o=- 1 2 IN IP4 127.0.0.1\r\n\
a=candidate:1 1 udp 2122260223 8.8.4.7 50000 typ srflx raddr 0.0.0.0 rport 0\r\n\
a=candidate:2 1 udp 2122260223 9.9.9.9 50001 typ srflx raddr 0.0.0.0 rport 0\r\n\
a=candidate:3 1 udp 2122260223 192.168.1.4 50002 typ host\r\n\
a=candidate:4 1 UDP 2122260223 4c9b8f2e-1d.local 50003 typ host\r\n\
a=candidate:5 1 tcp 1518280447 192.168.1.4 9 typ host tcptype active\r\n\
a=candidate:6 1 udp 2122260223 224.0.0.251 5353 typ host\r\n\
a=candidate:7 1 udp 2122260223 0.0.0.0 50004 typ host\r\n\
a=candidate:8 1 udp 2122260223 255.255.255.255 50005 typ host\r\n\
a=candidate:9 1 udp 2122260223 victim.example.com 50006 typ host\r\n\
a=candidate:10 1 udp 2122260223 8.8.4.7 0 typ host\r\n\
a=candidate:11 1 udp 2122260223 ::ffff:224.0.0.1 50007 typ host\r\n\
a=candidate:12 garbage\r\n\
a=end-of-candidates\r\n";

    /// The foundations of the candidates `sdp` keeps, in order.
    fn candidates(sdp: &str) -> Vec<&str> {
        sdp.lines()
            .filter_map(|line| line.strip_prefix("a=candidate:"))
            .filter_map(|candidate| candidate.split(' ').next())
            .collect()
    }

    #[test]
    fn a_swarm_sdp_keeps_only_candidates_a_receiver_may_try() {
        let all = constrain_swarm_sdp(SDP, |_| true);
        assert_eq!(candidates(&all), ["1", "2", "3", "4"]);
        // Everything that is not a candidate stays as it was.
        assert!(all.starts_with("v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n"));
        assert!(all.ends_with("a=end-of-candidates\r\n"));
        // `keep` decides the rest: here, only the sender's own public address
        // and local ones.
        let own: IpAddr = "8.8.4.7".parse().unwrap();
        let theirs =
            constrain_swarm_sdp(SDP, |ip| ip.is_none_or(|ip| !is_global_ip(ip) || ip == own));
        assert_eq!(candidates(&theirs), ["1", "3", "4"]);
        assert_eq!(
            candidates(&constrain_swarm_sdp(SDP, |ip| ip.is_some())),
            ["1", "2", "3"]
        );
    }

    #[test]
    fn a_swarm_sdp_keeps_at_most_the_candidate_limit() {
        use std::fmt::Write;
        let mut many = String::new();
        for n in 0..MAX_SWARM_CANDIDATES + 5 {
            let _ = write!(
                many,
                "a=candidate:{n} 1 udp 1 192.168.1.{n} 4000 typ host\r\n"
            );
        }
        let kept = constrain_swarm_sdp(&many, |_| true);
        assert_eq!(candidates(&kept).len(), MAX_SWARM_CANDIDATES);
        assert_eq!(candidates(&kept).first(), Some(&"0"));
    }

    #[test]
    fn only_the_standard_form_of_a_candidate_or_fingerprint_stays() {
        use std::fmt::Write;
        let sdp = "v=0\r\n\
a=fingerprint:sha-256 AB:CD\r\n\
a= fingerprint:sha-256 EE:EE\r\n\
a=Fingerprint:sha-256 EE:EE\r\n\
a=fingerprint sha-256 EE:EE\r\n\
a=candidate:1 1 udp 1 192.168.1.1 4000 typ host\r\n\
a= candidate:2 1 udp 1 192.168.1.2 4000 typ host\r\n\
a=\tcandidate:3 1 udp 1 192.168.1.3 4000 typ host\r\n\
a=CANDIDATE:4 1 udp 1 192.168.1.4 4000 typ host\r\n\
a=candidate :5 1 udp 1 192.168.1.5 4000 typ host\r\n\
a=candidate 6 1 udp 1 192.168.1.6 4000 typ host\r\n\
a=candidate: 7 1 udp 1 192.168.1.7 4000 typ host\r\n\
a=candidate:8 1 udp 1 192.168.1.8 4000 typ host \r\n\
\x20a=candidate:9 1 udp 1 192.168.1.9 4000 typ host\r\n\
A=candidate:10 1 udp 1 192.168.1.10 4000 typ host\r\n\
\ra=candidate:11 1 udp 1 192.168.1.11 4000 typ host\r\n\
a=candidate:12 1 udp 1 192.168.1.12 4000 typ host\ra=candidate:13 1 udp 1 1.2.3.4 9 typ host\n\
a=candidate\r\n\
a=candidates:14 1 udp 1 192.168.1.14 4000 typ host\n\
a=candidate:15 1 udp 1 192.168.1.15 4000 typ host\n\
a=candidate:16 1 udp 1\u{a0}127.0.0.1\u{a0}4444\u{a0}typ\u{a0}host 192.168.1.16 5000 typ host\r\n\
a=candidate:17 1 udp 1\t127.0.0.1\t4444 typ host\r\n\
a=candidate:18 1 udp 1  192.168.1.18 4000 typ host\r\n\
a=fingerprint:sha-256\u{2003}EE:EE\r\n\
a=candidate:19 257 udp 0 192.168.1.19 4000 typ host\r\n\
a=candidate:20 0 udp 1 192.168.1.20 4000 typ host\r\n\
a=candidate:21 1 udp -1 192.168.1.21 4000 typ host\r\n\
a=candidate:22 256 udp 0 192.168.1.22 4000 typ host\r\n\
a=end-of-candidates";
        let kept = constrain_swarm_sdp(sdp, |_| true);
        assert_eq!(
            kept,
            "v=0\r\n\
a=fingerprint:sha-256 AB:CD\r\n\
a=candidate:1 1 udp 1 192.168.1.1 4000 typ host\r\n\
a=candidates:14 1 udp 1 192.168.1.14 4000 typ host\n\
a=candidate:15 1 udp 1 192.168.1.15 4000 typ host\n\
a=candidate:22 256 udp 0 192.168.1.22 4000 typ host\r\n\
a=end-of-candidates"
        );
        // Only standard candidates count toward the limit, and are kept.
        let mut many = String::new();
        for n in 0..MAX_SWARM_CANDIDATES * 2 {
            let spelling = ["a=candidate:", "a= candidate:"][n % 2];
            let _ = write!(
                many,
                "{spelling}{n} 1 udp 1 192.168.1.{n} 4000 typ host\r\n"
            );
        }
        let kept = constrain_swarm_sdp(&many, |_| true);
        assert_eq!(candidates(&kept).len(), MAX_SWARM_CANDIDATES);
        assert_eq!(kept.lines().count(), MAX_SWARM_CANDIDATES);
    }

    #[test]
    fn a_mostly_dropped_sdp_holds_only_what_it_keeps() {
        let mut sdp = String::from("v=0\r\n");
        while sdp.len() < MAX_SWARM_SDP_BYTES - 64 {
            sdp.push_str("a=candidate:1 1 udp 1 9.9.9.9 4000 typ host\r\n");
        }
        let kept = constrain_swarm_sdp(&sdp, |ip| ip.is_none());
        assert_eq!(kept, "v=0\r\n");
        assert!(
            kept.capacity() < 64,
            "{} bytes held for a 5-byte SDP",
            kept.capacity()
        );
    }

    #[test]
    fn global_addresses_are_told_from_local_ones() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "2a00:1450:4001::1",
            "2606:4700::1111",
            "::ffff:8.8.8.8",
            // Either side of the IPv6 documentation prefix 3fff::/20.
            "3ffe:ffff::1",
            "3fff:1000::1",
            "3ff1::1",
        ] {
            assert!(is_global_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.1.2.3",
            "255.255.255.255",
            "224.0.0.1",
            "::1",
            "::",
            "fe80::1",
            "fd00::1",
            "ff02::1",
            "::ffff:192.168.1.1",
            // Documentation, benchmarking, IETF assignments, reserved.
            "192.0.2.1",
            "198.51.100.4",
            "203.0.113.7",
            "198.18.0.1",
            "198.19.255.1",
            "192.0.0.8",
            "192.88.99.1",
            "240.0.0.1",
            "2001:db8::1",
            "2001::1",
            "3fff::1",
            "3fff:0fff::1",
            "fec0::1",
            "64:ff9b:1::1",
            "100::1",
        ] {
            assert!(!is_global_ip(ip.parse().unwrap()), "{ip}");
        }
        assert_eq!(
            canonical_ip("::ffff:198.51.100.4".parse().unwrap()),
            "198.51.100.4".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_swarm_reply_error_is_bounded() {
        let short = ProtocolError::Internal("no".into());
        let long = ProtocolError::Internal("x".repeat(MAX_SWARM_ERROR_BYTES));
        assert!(SwarmAnswerResponse::Error(short.clone()).validate().is_ok());
        assert!(SwarmLeaveResponse::Error(short.clone()).validate().is_ok());
        assert!(SwarmAnnounceResponse::Error(short).validate().is_ok());
        assert!(SwarmAnswerResponse::Error(long.clone()).validate().is_err());
        assert!(SwarmLeaveResponse::Error(long.clone()).validate().is_err());
        assert!(SwarmAnnounceResponse::Error(long).validate().is_err());
        assert!(SwarmAnswerResponse::Delivered.validate().is_ok());
        assert!(SwarmLeaveResponse::Left.validate().is_ok());
    }

    #[test]
    fn a_signal_outlives_the_longest_announce_wait() {
        assert!(SWARM_SIGNAL_TTL_MS > u64::from(MAX_SWARM_WAIT_MS));
    }

    fn offer(id: u8, sdp_len: usize) -> SwarmOffer {
        SwarmOffer {
            offer_id: [id; 16],
            sdp: "v".repeat(sdp_len),
        }
    }

    #[test]
    fn announce_limits() {
        let ok = SwarmAnnounceRequest {
            room: [1; 32],
            node: [2; 32],
            membership: u64::MAX,
            offers: (0..8).map(|id| offer(id, MAX_SWARM_SDP_BYTES)).collect(),
            wait_ms: MAX_SWARM_WAIT_MS,
        };
        assert!(ok.validate().is_ok());
        let mut too_many = ok.clone();
        too_many.offers.push(offer(9, 10));
        assert!(too_many.validate().is_err());
        let mut too_large = ok.clone();
        if let Some(first) = too_large.offers.first_mut() {
            *first = offer(0, MAX_SWARM_SDP_BYTES + 1);
        }
        assert!(too_large.validate().is_err());
        let mut too_long = ok;
        too_long.wait_ms = MAX_SWARM_WAIT_MS + 1;
        assert!(too_long.validate().is_err());
    }

    #[test]
    fn a_list_past_its_limit_is_refused_while_decoding() {
        let encode = |offers: usize| {
            crate::ChunkMessage {
                request_id: 1,
                body: crate::ChunkMessageBody::SwarmAnnounceRequest(SwarmAnnounceRequest {
                    room: [1; 32],
                    node: [2; 32],
                    membership: 1,
                    offers: (0..offers)
                        .map(|id| offer(u8::try_from(id).unwrap_or(u8::MAX), 0))
                        .collect(),
                    wait_ms: 0,
                }),
            }
            .encode()
            .unwrap()
        };
        assert!(crate::ChunkMessage::decode(&encode(MAX_SWARM_OFFERS)).is_ok());
        // Thousands of empty offers fit a request's length; none decodes.
        assert!(crate::ChunkMessage::decode(&encode(MAX_SWARM_OFFERS + 1)).is_err());
        assert!(crate::ChunkMessage::decode(&encode(4096)).is_err());

        let reply = |signals: usize, servers: usize| {
            crate::ChunkMessage {
                request_id: 1,
                body: crate::ChunkMessageBody::SwarmAnnounceResponse(joined(
                    (0..signals)
                        .map(|n| SwarmSignal::Offer {
                            from: [0; 16],
                            offer_id: [u8::try_from(n).unwrap_or(u8::MAX); 16],
                            sdp: String::new(),
                        })
                        .collect(),
                    vec!["stun:203.0.113.5:10000".to_string(); servers],
                )),
            }
            .encode()
            .unwrap()
        };
        assert!(
            crate::ChunkMessage::decode(&reply(MAX_SWARM_INBOX, MAX_SWARM_ICE_SERVERS)).is_ok()
        );
        assert!(crate::ChunkMessage::decode(&reply(MAX_SWARM_INBOX + 1, 0)).is_err());
        assert!(crate::ChunkMessage::decode(&reply(0, MAX_SWARM_ICE_SERVERS + 1)).is_err());
    }

    #[test]
    fn the_largest_announce_fits_the_request_bound() {
        let largest = crate::ChunkMessage {
            request_id: u64::MAX,
            body: crate::ChunkMessageBody::SwarmAnnounceRequest(SwarmAnnounceRequest {
                room: [1; 32],
                node: [2; 32],
                membership: u64::MAX,
                offers: (0..8).map(|id| offer(id, MAX_SWARM_SDP_BYTES)).collect(),
                wait_ms: MAX_SWARM_WAIT_MS,
            }),
        };
        let encoded = largest.encode().unwrap();
        assert!(
            encoded.len() <= MAX_SWARM_REQUEST_BYTES,
            "{}",
            encoded.len()
        );
    }

    fn joined(inbox: Vec<SwarmSignal>, ice_servers: Vec<String>) -> SwarmAnnounceResponse {
        SwarmAnnounceResponse::Joined {
            member: [1; 16],
            members: 2,
            offers_delivered: 0,
            inbox,
            ice_servers,
        }
    }

    fn signal(sdp_len: usize) -> SwarmSignal {
        SwarmSignal::Offer {
            from: [2; 16],
            offer_id: [3; 16],
            sdp: "v".repeat(sdp_len),
        }
    }

    #[test]
    fn a_reply_counts_no_more_offers_than_an_announce_carries() {
        let mut reply = joined(Vec::new(), Vec::new());
        if let SwarmAnnounceResponse::Joined {
            offers_delivered, ..
        } = &mut reply
        {
            *offers_delivered = u32::try_from(MAX_SWARM_OFFERS).unwrap_or(u32::MAX);
        }
        assert!(reply.validate().is_ok());
        if let SwarmAnnounceResponse::Joined {
            offers_delivered, ..
        } = &mut reply
        {
            *offers_delivered = u32::MAX;
        }
        assert!(reply.validate().is_err());
    }

    #[test]
    fn reply_limits() {
        let stun = || "stun:203.0.113.5:10000".to_string();
        let full = (0..3).map(|_| signal(MAX_SWARM_SDP_BYTES)).collect();
        assert!(joined(full, vec![stun(); MAX_SWARM_ICE_SERVERS])
            .validate()
            .is_ok());
        assert!(joined((0..33).map(|_| signal(1)).collect(), Vec::new())
            .validate()
            .is_err());
        assert!(joined(vec![signal(MAX_SWARM_SDP_BYTES + 1)], Vec::new())
            .validate()
            .is_err());
        assert!(joined(
            (0..4).map(|_| signal(MAX_SWARM_SDP_BYTES)).collect(),
            Vec::new()
        )
        .validate()
        .is_err());
        assert!(joined(Vec::new(), vec![stun(); MAX_SWARM_ICE_SERVERS + 1])
            .validate()
            .is_err());
        let long = format!("stun:{}", "a".repeat(MAX_SWARM_ICE_SERVER_BYTES));
        assert!(joined(Vec::new(), vec![long]).validate().is_err());
        assert!(SwarmAnnounceResponse::Refused(SwarmRefusal::Busy)
            .validate()
            .is_ok());
    }

    /// The first byte postcard writes for an enum value is its variant's
    /// position. These must never change.
    fn tag<T: Serialize>(value: &T) -> u8 {
        postcard::to_stdvec(value)
            .unwrap()
            .first()
            .copied()
            .unwrap()
    }

    #[test]
    fn every_variant_keeps_its_wire_tag() {
        let error = || ProtocolError::Internal(String::new());
        let answer = SwarmSignal::Answer {
            from: [0; 16],
            offer_id: [0; 16],
            sdp: String::new(),
        };
        assert_eq!((tag(&signal(0)), tag(&answer)), (0, 1));
        let announce = [
            tag(&joined(Vec::new(), Vec::new())),
            tag(&SwarmAnnounceResponse::Refused(SwarmRefusal::Busy)),
            tag(&SwarmAnnounceResponse::Error(error())),
        ];
        assert_eq!(announce, [0, 1, 2]);
        let refusals = [
            SwarmRefusal::RoomFull,
            SwarmRefusal::TooManyRooms,
            SwarmRefusal::TooManyRoomsForPeer,
            SwarmRefusal::Busy,
            SwarmRefusal::Superseded,
            SwarmRefusal::NotHosting,
        ]
        .map(|refusal| tag(&refusal));
        assert_eq!(refusals, [0, 1, 2, 3, 4, 5]);
        let answers = [
            tag(&SwarmAnswerResponse::Delivered),
            tag(&SwarmAnswerResponse::Unmatched),
            tag(&SwarmAnswerResponse::Error(error())),
        ];
        assert_eq!(answers, [0, 1, 2]);
        assert_eq!(tag(&SwarmLeaveResponse::Left), 0);
        assert_eq!(tag(&SwarmLeaveResponse::Error(error())), 1);
    }

    #[test]
    fn answer_limits() {
        let mut answer = SwarmAnswerRequest {
            room: [1; 32],
            node: [4; 32],
            to: [2; 16],
            offer_id: [3; 16],
            sdp: "v".repeat(MAX_SWARM_SDP_BYTES),
        };
        assert!(answer.validate().is_ok());
        answer.sdp.push('v');
        assert!(answer.validate().is_err());
    }
}
