//! Prepare's checks and the names prepared forms are recorded under.
use super::{Vendor, digest};
use crate::module::{Result, prepare_platform, prepare_route, refused};
use drydock_protocol::*;

/// A reference pinned by sha256 digest, its name made only of the
/// characters an image reference uses (letters, digits, `.`, `_`, `-`, `/`
/// and a port's or tag's `:`), so nothing a Dockerfile line or a shell word
/// could carry rides beside it.
pub fn pinned(reference: &str) -> bool {
    reference.split_once("@sha256:").is_some_and(|(image, digest)| {
        !image.is_empty()
            && image.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-/:".contains(&b))
            && digest.len() == 64
            && digest.bytes().all(|b| b.is_ascii_hexdigit())
    })
}

/// What a prepare request must be before a vendor sees it: one of the
/// module's routes, both images pinned by digest, and the one platform
/// the vendor runs. Returns the route and platform.
pub fn check_prepare(
    vendor: Vendor,
    r: &PrepareRequest,
    routes: &[ImageRouteKind],
    platform: &Platform,
) -> Result<(ImageRouteKind, Platform)> {
    let route = prepare_route(r)?;
    if !routes.contains(&route) {
        return Err(refused(format!("{vendor} declares no {route} image route")));
    }
    if !pinned(&r.image_digest) {
        return Err(refused(format!("{vendor} requires an image reference pinned by sha256 digest")));
    }
    if !pinned(&r.tools_digest) {
        return Err(refused(format!("{vendor} requires a published tools image pinned by sha256 digest")));
    }
    let requested = prepare_platform(r)?;
    if requested != *platform {
        return Err(ProtocolError::ImageRefused {
            reason: format!("{vendor} runs only {platform} sandboxes"),
            refusal: ImageRefusal::UnsupportedPlatform { platform: requested },
        });
    }
    Ok((route, requested))
}

/// A deterministic resource name: `prefix` and the first `chars` hex digits
/// of the digest of `parts` joined by NUL. Content-addressed names never
/// change content, so a found one is never rebuilt.
pub fn content_name(prefix: &str, chars: usize, parts: &[&str]) -> String {
    format!("{prefix}{}", &digest(&parts.join("\0"))[..chars])
}

/// The prepared form belongs to this provider and names what `expected` does.
pub fn check_prepared(vendor: Vendor, provider: &str, prepared: &Prepared, expected: &str) -> Result<()> {
    if prepared.provider != provider {
        return Err(refused("prepared form belongs to another provider"));
    }
    if prepared.id != expected {
        return Err(refused(format!("{vendor} size does not match the prepared form")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pins() {
        let digest = "1".repeat(64);
        assert!(pinned(&format!("ghcr.io/a/b@sha256:{digest}")));
        for bad in [
            format!("@sha256:{digest}"),
            "ghcr.io/a/b:latest".into(),
            format!("a b@sha256:{digest}"),
            format!("a@sha256:{}", "z".repeat(64)),
            format!("a;rm@sha256:{digest}"),
            format!("a$HOME@sha256:{digest}"),
            format!("a\\b@sha256:{digest}"),
            format!("a@sha256:{digest}\n"),
        ] {
            assert!(!pinned(&bad), "{bad}");
        }
    }
}
