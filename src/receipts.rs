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
/// only so a pathological caller cannot grow the table. Minting fails rather
/// than invalidating a live receipt when the bound is reached.
const MAX_RECEIPTS: usize = 32;

struct Entry {
    // The Vec moves this pointer, not credential bytes, during reallocation,
    // removal, and retention.
    id: Zeroizing<Box<[u8]>>,
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
    /// Mint a zeroizing receipt for a completed authorization.
    pub fn mint(&mut self, cap: &Capability, now: Instant) -> std::io::Result<Zeroizing<String>> {
        self.sweep(now);
        if self.entries.len() >= MAX_RECEIPTS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "too many outstanding receipts",
            ));
        }
        let mut random = std::fs::File::open("/dev/urandom")?;
        loop {
            let mut id = Zeroizing::new(vec![0_u8; RECEIPT_LEN].into_boxed_slice());
            random.read_exact(id.as_mut())?;
            let candidate: &[u8] = id.as_ref();
            let duplicate = self
                .entries
                .iter()
                .fold(subtle::Choice::from(0), |found, entry| {
                    let stored: &[u8] = entry.id.as_ref();
                    found | stored.ct_eq(candidate)
                });
            if !bool::from(duplicate) {
                let receipt = hex(id.as_ref());
                self.entries.push(Entry {
                    id,
                    cap: cap.clone(),
                    minted: now,
                });
                return Ok(receipt);
            }
        }
    }

    /// Consume a receipt for the expected capability at most once, within TTL.
    pub fn redeem(
        &mut self,
        receipt_hex: &str,
        expected_cap: &Capability,
        now: Instant,
    ) -> Option<Capability> {
        self.sweep(now);
        let presented = parse_hex(receipt_hex)?;
        let presented: &[u8] = presented.as_ref();
        let mut position = 0;
        let mut found = subtle::Choice::from(0);
        for (index, entry) in self.entries.iter().enumerate() {
            let stored: &[u8] = entry.id.as_ref();
            let matches = stored.ct_eq(presented);
            let mask = 0_usize.wrapping_sub(usize::from((matches & !found).unwrap_u8()));
            position = (position & !mask) | (index & mask);
            found |= matches;
        }
        if bool::from(found)
            && self
                .entries
                .get(position)
                .is_some_and(|entry| entry.cap == *expected_cap)
        {
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

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

#[allow(
    clippy::indexing_slicing,
    reason = "each masked nibble is in 0..16 before the static lookup"
)]
fn hex(bytes: &[u8]) -> Zeroizing<String> {
    let mut rendered = Zeroizing::new(String::with_capacity(RECEIPT_LEN * 2));
    for &byte in bytes {
        rendered.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        rendered.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    rendered
}

fn parse_hex(raw: &str) -> Option<Zeroizing<Box<[u8]>>> {
    if raw.len() != RECEIPT_LEN * 2 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut parsed = Zeroizing::new(vec![0_u8; RECEIPT_LEN].into_boxed_slice());
    for (slot, chunk) in parsed.iter_mut().zip(raw.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(parsed)
}
#[cfg(test)]
mod tests {
    use std::time::Instant;

    use zeroize::Zeroize as _;

    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_receipt_redeems_exactly_once_and_expires() {
        let mut table = ReceiptTable::default();
        let now = Instant::now();
        let cap = Capability::parse("browser").unwrap();
        let receipt = table.mint(&cap, now).unwrap();
        assert_eq!(receipt.len(), RECEIPT_LEN * 2);

        assert_eq!(
            table.redeem(&receipt, &cap, now).unwrap().as_str(),
            "browser"
        );
        assert!(
            table.redeem(&receipt, &cap, now).is_none(),
            "second redeem must fail"
        );

        let stale = table.mint(&cap, now).unwrap();
        assert!(
            table.redeem(&stale, &cap, now + RECEIPT_TTL).is_none(),
            "expired redeem must fail"
        );
    }

    #[test]
    fn redeem_rejects_malformed_hex_without_panicking() {
        let mut table = ReceiptTable::default();
        let cap = Capability::parse("browser").unwrap();
        assert!(table.redeem("zz", &cap, Instant::now()).is_none());
        assert!(
            table
                .redeem(&"a".repeat(63), &cap, Instant::now())
                .is_none()
        );
    }

    #[test]
    fn redeeming_seeded_receipt_scans_and_consumes_it() {
        let now = Instant::now();
        let browser = Capability::parse("browser").unwrap();
        let admin = Capability::parse("admin").unwrap();
        let browser_expected = browser.clone();
        let admin_expected = admin.clone();
        let mut table = ReceiptTable {
            entries: vec![
                Entry {
                    id: Zeroizing::new(vec![0x42; RECEIPT_LEN].into_boxed_slice()),
                    cap: browser,
                    minted: now,
                },
                Entry {
                    id: Zeroizing::new(vec![0x24; RECEIPT_LEN].into_boxed_slice()),
                    cap: admin,
                    minted: now,
                },
            ],
        };
        let browser_receipt = Zeroizing::new("42".repeat(RECEIPT_LEN));
        let admin_receipt = Zeroizing::new("24".repeat(RECEIPT_LEN));

        let redeemed = table.redeem(&browser_receipt, &browser_expected, now);

        assert_eq!(redeemed.as_ref().map(Capability::as_str), Some("browser"));
        assert_eq!(
            table
                .redeem(&admin_receipt, &admin_expected, now)
                .as_ref()
                .map(Capability::as_str),
            Some("admin")
        );
        assert!(table.entries.is_empty());
    }

    #[test]
    fn mismatched_capability_does_not_consume_a_receipt() {
        let browser = Capability::parse("browser").unwrap();
        let admin = Capability::parse("admin").unwrap();
        let now = Instant::now();
        let receipt = Zeroizing::new("42".repeat(RECEIPT_LEN));
        let mut table = ReceiptTable {
            entries: vec![Entry {
                id: Zeroizing::new(vec![0x42; RECEIPT_LEN].into_boxed_slice()),
                cap: browser.clone(),
                minted: now,
            }],
        };

        assert!(table.redeem(&receipt, &admin, now).is_none());
        assert_eq!(
            table.redeem(&receipt, &browser, now).unwrap().as_str(),
            "browser"
        );
    }

    #[test]
    fn rendered_receipt_is_a_zeroizing_string() {
        let mut receipt: Zeroizing<String> = hex(&[0xab; RECEIPT_LEN]);

        assert_eq!(receipt.len(), RECEIPT_LEN * 2);
        receipt.zeroize();
        assert!(receipt.is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn clear_forgets_every_outstanding_receipt() {
        let mut table = ReceiptTable::default();
        let cap = Capability::parse("browser").unwrap();
        let now = Instant::now();
        let receipt = table.mint(&cap, now).unwrap();

        table.clear();

        assert!(
            table.redeem(&receipt, &cap, now).is_none(),
            "a cleared receipt must be dead"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn sweep_removes_expired_receipts_without_redemption() {
        let mut table = ReceiptTable::default();
        let cap = Capability::parse("browser").unwrap();
        let now = Instant::now();
        let receipt = table.mint(&cap, now).unwrap();

        table.sweep(now + RECEIPT_TTL);

        assert!(table.entries.is_empty());
        assert!(table.redeem(&receipt, &cap, now + RECEIPT_TTL).is_none());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn mint_at_capacity_refuses_without_revoking_receipts() {
        let mut table = ReceiptTable::default();
        let cap = Capability::parse("browser").unwrap();
        let now = Instant::now();
        let mut receipts = Vec::with_capacity(MAX_RECEIPTS);
        for _ in 0..MAX_RECEIPTS {
            receipts.push(table.mint(&cap, now).unwrap());
        }

        let error = table.mint(&cap, now).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        for receipt in receipts {
            let redeemed = table.redeem(&receipt, &cap, now);
            assert_eq!(redeemed.as_ref().map(Capability::as_str), Some("browser"));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn full_table_keeps_the_oldest_receipt() {
        let mut table = ReceiptTable::default();
        let cap = Capability::parse("browser").unwrap();
        let now = Instant::now();
        let oldest = table.mint(&cap, now).unwrap();
        for _ in 1..MAX_RECEIPTS {
            table.mint(&cap, now).unwrap();
        }

        assert!(table.mint(&cap, now).is_err());

        let redeemed = table.redeem(&oldest, &cap, now);
        assert_eq!(redeemed.as_ref().map(Capability::as_str), Some("browser"));
    }

    #[test]
    fn mint_refuses_an_over_capacity_table_without_reducing_it() {
        let mut table = ReceiptTable::default();
        let cap = Capability::parse("browser").unwrap();
        let now = Instant::now();
        for _ in 0..=MAX_RECEIPTS {
            table.entries.push(Entry {
                id: Zeroizing::new(vec![0_u8; RECEIPT_LEN].into_boxed_slice()),
                cap: cap.clone(),
                minted: now,
            });
        }

        let error = table.mint(&cap, now).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(table.entries.len(), MAX_RECEIPTS + 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn mint_returns_a_zeroizing_string() {
        let mut table = ReceiptTable::default();
        let cap = Capability::parse("browser").unwrap();
        let now = Instant::now();
        let mut receipt: Zeroizing<String> = table.mint(&cap, now).unwrap();

        assert_eq!(receipt.len(), RECEIPT_LEN * 2);
        receipt.zeroize();
        assert!(receipt.is_empty());
    }
}
