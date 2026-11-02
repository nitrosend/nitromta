//! What the load generator and the sink record about each message, and the
//! fixed-size little-endian form in which the records leave their containers.

use std::net::{IpAddr, Ipv6Addr};

pub const ACK_LEN: usize = 34;
pub const ARRIVAL_LEN: usize = 35;

/// One submission, as the load generator saw it. Times are microseconds since
/// the Unix epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub id: u64,
    /// When the offered rate made the message due. A generator that falls
    /// behind still measures from here, so a system that stalls it is charged
    /// for the wait.
    pub due: i64,
    pub sent: i64,
    /// When the final reply arrived, or the connection failed.
    pub replied: i64,
    /// The final reply's code, or 0 when the connection failed first.
    pub code: u16,
}

impl Ack {
    pub fn accepted(&self) -> bool {
        (200..300).contains(&self.code)
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&self.due.to_le_bytes());
        out.extend_from_slice(&self.sent.to_le_bytes());
        out.extend_from_slice(&self.replied.to_le_bytes());
        out.extend_from_slice(&self.code.to_le_bytes());
    }

    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Self>, String> {
        if !bytes.len().is_multiple_of(ACK_LEN) {
            return Err(format!(
                "{} bytes of acknowledgements are not whole records",
                bytes.len()
            ));
        }
        Ok(bytes
            .as_chunks::<ACK_LEN>()
            .0
            .iter()
            .map(|record| Self {
                id: u64::from_le_bytes(field(record, 0)),
                due: i64::from_le_bytes(field(record, 8)),
                sent: i64::from_le_bytes(field(record, 16)),
                replied: i64::from_le_bytes(field(record, 24)),
                code: u16::from_le_bytes(field(record, 32)),
            })
            .collect())
    }
}

/// One recipient's copy of a message the sink received, with the checks the
/// message passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arrival {
    /// The load generator's id, or 0 when the message carried none.
    pub id: u64,
    /// Which of the message's recipients it reached: the index after its
    /// address's id, or 0 for an address with none.
    pub recipient: u16,
    /// When the sink read the end of the message.
    pub at: i64,
    pub checks: u8,
    /// The address its session came from: the system's egress.
    pub source: IpAddr,
}

impl Arrival {
    /// A valid DKIM signature by the expected domain and selector.
    pub const DKIM: u8 = 1;
    /// The body is byte for byte the one the load generator sent.
    pub const BODY: u8 = 2;
    /// It arrived over TLS.
    pub const TLS: u8 = 4;
    /// It carried the load generator's id.
    pub const IDENTIFIED: u8 = 8;

    pub fn passed(&self, check: u8) -> bool {
        self.checks & check == check
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.id.to_le_bytes());
        out.extend_from_slice(&self.recipient.to_le_bytes());
        out.extend_from_slice(&self.at.to_le_bytes());
        out.push(self.checks);
        let source = match self.source {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        };
        out.extend_from_slice(&source.octets());
    }

    pub fn decode_all(bytes: &[u8]) -> Result<Vec<Self>, String> {
        if !bytes.len().is_multiple_of(ARRIVAL_LEN) {
            return Err(format!(
                "{} bytes of arrivals are not whole records",
                bytes.len()
            ));
        }
        Ok(bytes
            .as_chunks::<ARRIVAL_LEN>()
            .0
            .iter()
            .map(|record| Self {
                id: u64::from_le_bytes(field(record, 0)),
                recipient: u16::from_le_bytes(field(record, 8)),
                at: i64::from_le_bytes(field(record, 10)),
                checks: record[18],
                source: Ipv6Addr::from(field::<16>(record, 19)).to_canonical(),
            })
            .collect())
    }
}

fn field<const N: usize>(record: &[u8], at: usize) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(&record[at..at + N]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_round_trip() {
        let acks = [
            Ack {
                id: 1,
                due: -5,
                sent: 7,
                replied: i64::MAX,
                code: 250,
            },
            Ack {
                id: u64::MAX,
                due: 0,
                sent: 0,
                replied: 0,
                code: 0,
            },
        ];
        let mut bytes = Vec::new();
        acks.iter().for_each(|ack| ack.encode(&mut bytes));
        assert_eq!(bytes.len(), 2 * ACK_LEN);
        assert_eq!(Ack::decode_all(&bytes).unwrap(), acks);
        assert!(Ack::decode_all(&bytes[1..]).is_err());

        let arrival = Arrival {
            id: 9,
            recipient: 49,
            at: 1_700_000_000_000_000,
            checks: Arrival::DKIM | Arrival::TLS,
            source: "10.89.0.11".parse().unwrap(),
        };
        let mut bytes = Vec::new();
        arrival.encode(&mut bytes);
        assert_eq!(bytes.len(), ARRIVAL_LEN);
        assert_eq!(Arrival::decode_all(&bytes).unwrap(), [arrival]);
        assert!(arrival.passed(Arrival::DKIM | Arrival::TLS));
        assert!(!arrival.passed(Arrival::BODY));
    }
}
