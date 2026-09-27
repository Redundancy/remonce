//! The signer's web UI, compiled into the binary: the layout, one template
//! per page, and the static script and stylesheet. Nothing is read from
//! disk at run time, so the binary is all a signer needs. Edit the files in
//! `ui/` and rebuild.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

/// The frame every page renders into.
pub const LAYOUT: &str = include_str!("../ui/layout.html");

/// The UI pages: `/ui/{name}` renders `template` inside [`LAYOUT`].
pub struct Page {
    pub name: &'static str,
    pub title: &'static str,
    pub template: &'static str,
}

pub const PAGES: &[Page] = &[
    Page { name: "commands", title: "Commands", template: include_str!("../ui/commands.html") },
    Page { name: "review", title: "Sign a request", template: include_str!("../ui/review.html") },
    Page { name: "execute", title: "Execute", template: include_str!("../ui/execute.html") },
    Page { name: "monitor", title: "Runs", template: include_str!("../ui/monitor.html") },
    Page { name: "files", title: "Files", template: include_str!("../ui/files.html") },
];

pub fn page(name: &str) -> Option<&'static Page> {
    PAGES.iter().find(|p| p.name == name)
}

struct Asset {
    name: &'static str,
    content_type: &'static str,
    body: &'static [u8],
}

const ASSETS: &[Asset] = &[
    Asset {
        name: "app.js",
        content_type: "text/javascript; charset=utf-8",
        body: include_bytes!("../ui/static/app.js"),
    },
    Asset {
        name: "remonce.css",
        content_type: "text/css; charset=utf-8",
        body: include_bytes!("../ui/static/remonce.css"),
    },
];

/// Strong ETags, from each asset's content.
static ETAGS: LazyLock<Vec<String>> = LazyLock::new(|| {
    ASSETS
        .iter()
        .map(|a| format!("\"{}\"", &hex::encode(Sha256::digest(a.body))[..16]))
        .collect()
});

/// `GET /static/{name}`: an embedded asset. Browsers revalidate each time
/// (`no-cache`) and get a 304 while the content is unchanged.
pub async fn static_handler(
    axum::extract::Path(name): axum::extract::Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(i) = ASSETS.iter().position(|a| a.name == name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (asset, etag) = (&ASSETS[i], &ETAGS[i]);
    let cache = [
        (header::ETAG, HeaderValue::from_str(etag).expect("hex etag")),
        (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
    ];
    let matches = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag));
    if matches {
        return (StatusCode::NOT_MODIFIED, cache).into_response();
    }
    (
        cache,
        [(header::CONTENT_TYPE, HeaderValue::from_static(asset.content_type))],
        asset.body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_page_has_a_template_and_the_layout_has_its_slots() {
        for p in PAGES {
            assert!(!p.template.trim().is_empty(), "{} is empty", p.name);
        }
        for slot in ["{{content}}", "{{page}}", "{{title}}", "{{agent_options}}", "{{hostname}}"] {
            assert!(LAYOUT.contains(slot), "layout lacks {slot}");
        }
    }

    #[test]
    fn layout_references_only_embedded_assets() {
        // Every /static/ reference in the layout must be served.
        for part in LAYOUT.split("/static/").skip(1) {
            let name = part.split(['?', '"']).next().unwrap();
            assert!(ASSETS.iter().any(|a| a.name == name), "layout references missing asset {name}");
        }
    }

    #[tokio::test]
    async fn assets_are_served_with_types_and_revalidation() {
        use axum::body::to_bytes;
        let get = |name: &str, inm: Option<&str>| {
            let mut h = HeaderMap::new();
            if let Some(v) = inm {
                h.insert(header::IF_NONE_MATCH, HeaderValue::from_str(v).unwrap());
            }
            static_handler(axum::extract::Path(name.to_string()), h)
        };
        let r = get("app.js", None).await;
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(r.headers()[header::CONTENT_TYPE], "text/javascript; charset=utf-8");
        let etag = r.headers()[header::ETAG].to_str().unwrap().to_string();
        assert_eq!(to_bytes(r.into_body(), usize::MAX).await.unwrap().len(), ASSETS[0].body.len());

        assert_eq!(get("app.js", Some(&etag)).await.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(get("app.js", Some("\"other\"")).await.status(), StatusCode::OK);
        assert_eq!(get("../config.toml", None).await.status(), StatusCode::NOT_FOUND);
        assert_eq!(get("remonce.css", None).await.headers()[header::CONTENT_TYPE], "text/css; charset=utf-8");
    }
}
