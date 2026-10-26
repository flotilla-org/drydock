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

/// Options plus, optionally, a completed upload to install in their place of
/// a request body: `WithBlob<FileOptions>` for files, `WithBlob<TreeOptions>`
/// for trees. Client and server share the option types themselves. serde's
/// `flatten` cannot carry the numeric options through a query string, so the
/// blob is split off by hand and the rest decoded as `T`, unknown names
/// still refused.
pub(crate) struct WithBlob<T> {
    pub options: T,
    pub blob: Option<String>,
}
impl<T: Serialize> WithBlob<T> {
    pub fn encode(&self) -> std::io::Result<String> {
        let options = serde_urlencoded::to_string(&self.options).map_err(crate::invalid)?;
        let blob = self.blob.as_ref().map(|blob| serde_urlencoded::to_string([("blob", blob)])).transpose().map_err(crate::invalid)?;
        let query = [Some(options), blob].into_iter().flatten().filter(|part| !part.is_empty()).collect::<Vec<_>>().join("&");
        Ok(if query.is_empty() { query } else { format!("?{query}") })
    }
}
impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for WithBlob<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let (blob, rest): (Vec<(String, String)>, Vec<_>) =
            Vec::<(String, String)>::deserialize(deserializer)?.into_iter().partition(|(name, _)| name == "blob");
        let blob = match &blob[..] {
            [] => None,
            [(_, blob)] => Some(blob.clone()),
            _ => return Err(D::Error::custom("blob is given more than once")),
        };
        let rest = serde_urlencoded::to_string(&rest).map_err(D::Error::custom)?;
        Ok(Self { options: serde_urlencoded::from_str(&rest).map_err(D::Error::custom)?, blob })
    }
}

/// Where a reattaching reader already is on each stream.
#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttachQuery {
    #[serde(default)]
    pub stdout: u64,
    #[serde(default)]
    pub stderr: u64,
}

/// A query string for `value`, with its leading `?` when nonempty.
pub(crate) fn encode(value: &impl Serialize) -> std::io::Result<String> {
    let query = serde_urlencoded::to_string(value).map_err(crate::invalid)?;
    Ok(if query.is_empty() { query } else { format!("?{query}") })
}
