use super::ErrCode;

/// A response to send back to a client.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Response<'a> {
    /// Success, no payload.
    Ok,
    /// Success with space-separated `k=v` fields.
    ///
    /// Space, not tab: `sanitize` collapses tabs so that a value can never
    /// inject an extra field, which also makes tab unusable as the separator.
    /// Field values must therefore not contain spaces.
    OkFields(&'a str),
    /// Success followed by exactly this many raw payload bytes.
    OkBytes(usize),
    /// Failure with a machine code and a human-readable reason.
    Failed(ErrCode, &'a str),
}

/// Render a response header line, including its trailing newline.
pub fn format_response(response: &Response<'_>) -> String {
    match response {
        Response::Ok => "OK\n".to_owned(),
        Response::OkFields(fields) => {
            let sanitized = sanitize(fields);
            // Fields are space-separated, and `sanitize` does not defend that
            // separator -- it only rewrites CR, LF and tab. So a value carrying
            // a space (or a tab, which becomes one here) would reach a client as
            // an extra field. Every value emitted today is a literal or hex, so
            // this is a tripwire for whoever adds the next field, not a runtime
            // guard: it is compiled out of release builds, and the invariant is
            // structural rather than something to branch on at run time.
            debug_assert!(
                sanitized
                    .split(' ')
                    .all(|field| !field.is_empty() && field.contains('=')),
                "OkFields payload is not space-separated k=v: {sanitized}"
            );
            format!("OK\t{sanitized}\n")
        }
        Response::OkBytes(len) => format!("OK\tlen={len}\n"),
        Response::Failed(code, message) => {
            format!("ERR\t{}\t{}\n", code.wire(), sanitize(message))
        }
    }
}

fn sanitize(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character == '\n' || character == '\r' || character == '\t' {
                ' '
            } else {
                character
            }
        })
        .collect()
}
