//! Single-use attestation receipts for capability authorizations.
//!
//! A receipt lets a process outside the session tree (forward serve) verify
//! with this daemon that a touch ceremony completed, without becoming able to
//! read anything. Receipts are not secrets-shaped: never persisted, never
//! logged, dead after one redeem or sixty seconds.

use std::io::Read as _;
use std::time::{Duration, Instant};

use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::capability::Capability;

/// Receipt entropy in bytes; hex-encoded on the wire (double this length).
pub const RECEIPT_LEN: usize = 32;
/// A receipt is redeemed by the very next hop; a minute is generous.
pub const RECEIPT_TTL: Duration = Duration::from_mins(1);
/// Receipts are minted one per successful touch ceremony; this bound exists
/// only so a pathological caller cannot grow the table.
const MAX_RECEIPTS: usize = 32;

struct Entry {
    id: Zeroizing<[u8; RECEIPT_LEN]>,
    cap: Capability,
    minted: Instant,
}

/// Outstanding receipts. No values live here.
#[derive(Default)]
pub struct ReceiptTable {
    entries: Vec<Entry>,
}

impl std::fmt::Debug for ReceiptTable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReceiptTable")
            .field("outstanding", &self.entries.len())
            .finish()
    }
}

impl ReceiptTable {
    /// Mint a receipt for a completed authorization.
    pub fn mint(&mut self, cap: &Capability, now: Instant) -> std::io::Result<String> {
        self.sweep(now);
        if self.entries.len() == MAX_RECEIPTS {
            self.entries.remove(0);
        }
        let mut random = std::fs::File::open("/dev/urandom")?;
        loop {
            let mut id = Zeroizing::new([0_u8; RECEIPT_LEN]);
            random.read_exact(&mut *id)?;
            let candidate: &[u8] = &*id;
            let duplicate = self
                .entries
                .iter()
                .fold(subtle::Choice::from(0), |found, entry| {
                    let stored: &[u8] = &*entry.id;
                    found | stored.ct_eq(candidate)
                });
            if !bool::from(duplicate) {
                let receipt = hex(&id);
                self.entries.push(Entry {
                    id,
                    cap: cap.clone(),
                    minted: now,
                });
                return Ok(receipt);
            }
        }
    }

    /// Consume a receipt: returns its capability at most once, within TTL.
    pub fn redeem(&mut self, receipt_hex: &str, now: Instant) -> Option<Capability> {
        self.sweep(now);
        let presented = parse_hex(receipt_hex)?;
        let presented: &[u8] = &*presented;
        let mut position = 0;
        let mut found = subtle::Choice::from(0);
        for (index, entry) in self.entries.iter().enumerate() {
            let stored: &[u8] = &*entry.id;
            let matches = stored.ct_eq(presented);
            let mask = 0_usize.wrapping_sub(usize::from((matches & !found).unwrap_u8()));
            position = (position & !mask) | (index & mask);
            found |= matches;
        }
        if bool::from(found) {
            Some(self.entries.swap_remove(position).cap)
        } else {
            None
        }
    }

    /// Drop expired receipts.
    pub fn sweep(&mut self, now: Instant) {
        self.entries
            .retain(|entry| now.duration_since(entry.minted) < RECEIPT_TTL);
    }

    /// Forget every outstanding receipt. `LOCK` calls this in the same
    /// critical section that revokes grants: a receipt is standing authority
    /// exactly like a grant, and an attestation minted before a lock must not
    /// outlive it.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

fn hex(bytes: &[u8; RECEIPT_LEN]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(RECEIPT_LEN * 2),
        |mut rendered, byte| {
            let _ = write!(rendered, "{byte:02x}");
            rendered
        },
    )
}

fn parse_hex(raw: &str) -> Option<Zeroizing<[u8; RECEIPT_LEN]>> {
    if raw.len() != RECEIPT_LEN * 2 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut parsed = Zeroizing::new([0_u8; RECEIPT_LEN]);
    for (index, chunk) in raw.as_bytes().chunks_exact(2).enumerate() {
        let value = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
        *parsed.get_mut(index)? = value;
    }
    Some(parsed)
}
#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn a_receipt_redeems_exactly_once_and_expires() {
        let mut table = ReceiptTable::default();
        let now = Instant::now();
        let cap = Capability::parse("browser").unwrap();
        let receipt = table.mint(&cap, now).unwrap();
        assert_eq!(receipt.len(), RECEIPT_LEN * 2);

        assert_eq!(table.redeem(&receipt, now).unwrap().as_str(), "browser");
        assert!(
            table.redeem(&receipt, now).is_none(),
            "second redeem must fail"
        );

        let stale = table.mint(&cap, now).unwrap();
        assert!(
            table.redeem(&stale, now + RECEIPT_TTL).is_none(),
            "expired redeem must fail"
        );
    }

    #[test]
    fn redeem_rejects_malformed_hex_without_panicking() {
        let mut table = ReceiptTable::default();
        assert!(table.redeem("zz", Instant::now()).is_none());
        assert!(table.redeem(&"a".repeat(63), Instant::now()).is_none());
    }

    #[test]
    fn clear_forgets_every_outstanding_receipt() {
        let mut table = ReceiptTable::default();
        let cap = Capability::parse("browser").unwrap();
        let now = Instant::now();
        let receipt = table.mint(&cap, now).unwrap();

        table.clear();

        assert!(
            table.redeem(&receipt, now).is_none(),
            "a cleared receipt must be dead"
        );
    }

    #[test]
    fn sweep_removes_expired_receipts_without_redemption() {
        let mut table = ReceiptTable::default();
        let cap = Capability::parse("browser").unwrap();
        let now = Instant::now();
        let receipt = table.mint(&cap, now).unwrap();

        table.sweep(now + RECEIPT_TTL);

        assert!(table.entries.is_empty());
        assert!(table.redeem(&receipt, now + RECEIPT_TTL).is_none());
    }
}
