//! Query strings, one type per route family, written by the client and read
//! by the server. Unknown parameters are refused, so a misspelt option is an
//! error rather than silently ignored. Absent options are left out.
use crate::FileOptions;
use serde::{Deserialize, Serialize};

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirQuery {
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    #[serde(default)]
    pub parents: bool,
    #[serde(default)]
    pub exclusive: bool,
}
impl From<&FileOptions> for DirQuery {
    fn from(options: &FileOptions) -> Self {
        Self { mode: options.mode, uid: options.uid, gid: options.gid, parents: options.parents, exclusive: options.exclusive }
    }
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LinkQuery {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    #[serde(default)]
    pub parents: bool,
    #[serde(default)]
    pub exclusive: bool,
}
impl From<&FileOptions> for LinkQuery {
    fn from(options: &FileOptions) -> Self {
        Self { uid: options.uid, gid: options.gid, parents: options.parents, exclusive: options.exclusive }
    }
}

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoveQuery {
    #[serde(default)]
    pub recursive: bool,
}

/// A query string for `value`, with its leading `?` when nonempty.
pub(crate) fn encode(value: &impl Serialize) -> std::io::Result<String> {
    let query = serde_urlencoded::to_string(value).map_err(crate::invalid)?;
    Ok(if query.is_empty() { query } else { format!("?{query}") })
}
