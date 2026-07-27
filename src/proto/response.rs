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
        Response::OkFields(fields) => format!("OK\t{}\n", sanitize(fields)),
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
