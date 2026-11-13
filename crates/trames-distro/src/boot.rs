// SPDX-License-Identifier: GPL-3.0-or-later
//! Cold product selection, independent of the CPU executor and Linux resources.
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    #[default]
    Linux,
    Android,
}
impl Target {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "linux" => Ok(Self::Linux),
            "android" => Ok(Self::Android),
            _ => Err("target must be linux or android"),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Android => "android",
        }
    }
}
