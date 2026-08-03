use std::path::Path;

use super::{HumanSource, HumanStore};
use crate::secret::SecretName;

fn name(raw: &str) -> SecretName {
    SecretName::parse(raw).unwrap()
}

fn source(label: &str, directory: &Path) -> HumanSource {
    HumanSource {
        label: label.to_owned(),
        dir: directory.to_path_buf(),
    }
}

#[path = "tests/basic.rs"]
mod basic;
#[path = "tests/multi_source.rs"]
mod multi_source;
