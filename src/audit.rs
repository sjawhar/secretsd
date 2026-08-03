//! Audit-value sanitization shared by the request audit line, the worker's
//! grant event, and the store's invalid-filename warning. One implementation
//! so the three log surfaces can never drift apart.

pub(crate) const MAX_AUDIT_VALUE_BYTES: usize = 256;

fn append_audit_piece(rendered: &mut String, piece: &str) -> bool {
    if rendered.len().saturating_add(piece.len()) > MAX_AUDIT_VALUE_BYTES {
        while rendered.len() > MAX_AUDIT_VALUE_BYTES.saturating_sub('…'.len_utf8()) {
            rendered.pop();
        }
        rendered.push('…');
        return false;
    }
    rendered.push_str(piece);
    true
}

pub(crate) fn sanitize_audit_value(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len().min(MAX_AUDIT_VALUE_BYTES));
    for character in value.chars() {
        let appended = match character {
            '\r' => append_audit_piece(&mut rendered, r"\r"),
            '\n' => append_audit_piece(&mut rendered, r"\n"),
            '\t' => append_audit_piece(&mut rendered, r"\t"),
            '\0' => append_audit_piece(&mut rendered, r"\0"),
            control if control.is_control() => {
                let escaped = format!(r"\u{{{:04X}}}", u32::from(control));
                append_audit_piece(&mut rendered, &escaped)
            }
            printable => {
                let mut encoded = [0; 4];
                append_audit_piece(&mut rendered, printable.encode_utf8(&mut encoded))
            }
        };
        if !appended {
            return rendered;
        }
    }
    rendered
}
