//! The agents a signer knows: `agent_url` and `allowed_agent_urls` from
//! `config.toml`, plus the user's own list in their per-user agents file.
//!
//! The signer proxies to an agent with the user's viewer token attached, so
//! it only talks to agents on this list; the UI offers exactly these.

use serde::Deserialize;
use std::path::PathBuf;

/// Overrides where the per-user agents file is read from.
pub const AGENTS_FILE_ENV: &str = "REMONCE_AGENTS_FILE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `agent_url` or `allowed_agent_urls` in `config.toml`.
    Config,
    /// The user's agents file.
    User,
}

#[derive(Debug, Clone)]
pub struct KnownAgent {
    /// Normalized to the origin (`https://host:port/`).
    pub url: url::Url,
    pub name: Option<String>,
    pub source: Source,
    /// A loopback host: the machine running the signer, which makes the call.
    pub local: bool,
}

impl KnownAgent {
    /// `https://host:port`, the form the UI sends back.
    pub fn origin(&self) -> String {
        self.url.origin().ascii_serialization()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserFile {
    #[serde(default)]
    agents: Vec<UserAgent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserAgent {
    url: String,
    name: Option<String>,
}

/// Normalize an agent URL to its origin. Only https is accepted — the agent
/// has no plaintext mode.
pub fn normalize(raw: &str) -> Result<url::Url, String> {
    let mut parsed: url::Url = raw
        .trim()
        .parse()
        .map_err(|e| format!("Invalid agent URL '{raw}': {e}"))?;
    if parsed.scheme() != "https" {
        return Err(format!(
            "Agent URL must be https (got '{raw}'); the agent has no plaintext mode"
        ));
    }
    if parsed.host_str().is_none() {
        return Err(format!("Agent URL '{raw}' has no host"));
    }
    parsed.set_path("/");
    parsed.set_query(None);
    parsed.set_fragment(None);
    Ok(parsed)
}

fn is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(d)) => {
            let d = d.to_ascii_lowercase();
            d == "localhost" || d.ends_with(".localhost")
        }
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Where the user's agents file lives: `$REMONCE_AGENTS_FILE`, else
/// `%APPDATA%\remonce\agents.toml` on Windows and
/// `$XDG_CONFIG_HOME/remonce/agents.toml` (or `~/.config/…`) elsewhere.
pub fn user_file_path() -> Option<PathBuf> {
    let env = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(p) = env(AGENTS_FILE_ENV) {
        return Some(p);
    }
    let base = if cfg!(windows) {
        env("APPDATA")
    } else {
        env("XDG_CONFIG_HOME").or_else(|| env("HOME").map(|h| h.join(".config")))
    };
    base.map(|b| b.join("remonce").join("agents.toml"))
}

/// Parse a user agents file's contents.
fn parse_user_file(text: &str) -> Result<Vec<(url::Url, Option<String>)>, String> {
    let file: UserFile = toml::from_str(text).map_err(|e| e.to_string())?;
    file.agents
        .into_iter()
        .map(|a| {
            let name = a.name.map(|n| n.trim().to_string()).filter(|n| !n.is_empty());
            Ok((normalize(&a.url)?, name))
        })
        .collect()
}

/// Build the list: config agents first (`agent_url` leading), then the
/// user's. An agent listed in both keeps its config place and takes the
/// user's name. A missing user file is fine; an unreadable or invalid one
/// is an error, as is an invalid URL anywhere.
pub fn load(config: &crate::config::Config) -> Result<Vec<KnownAgent>, String> {
    let user = match user_file_path() {
        Some(path) if path.exists() => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("Failed to read {}: {e}", path.display()))?;
            parse_user_file(&text).map_err(|e| format!("Invalid agents file {}: {e}", path.display()))?
        }
        _ => Vec::new(),
    };
    let from_config = std::iter::once(&config.agent_url)
        .chain(&config.allowed_agent_urls)
        .map(|u| normalize(u).map(|url| (url, None)))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(merge(from_config, user))
}

fn merge(
    from_config: Vec<(url::Url, Option<String>)>,
    user: Vec<(url::Url, Option<String>)>,
) -> Vec<KnownAgent> {
    let mut agents: Vec<KnownAgent> = Vec::new();
    let sources = from_config
        .into_iter()
        .map(|a| (a, Source::Config))
        .chain(user.into_iter().map(|a| (a, Source::User)));
    for ((url, name), source) in sources {
        if let Some(existing) = agents.iter_mut().find(|a| a.url.origin() == url.origin()) {
            if existing.name.is_none() {
                existing.name = name;
            }
            continue;
        }
        agents.push(KnownAgent {
            local: is_loopback(&url),
            url,
            name,
            source,
        });
    }
    agents
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// `<option>`s for the UI's agent picker, grouped: this machine, then
/// `config.toml`, then the user's. The first (the default) is selected.
pub fn options_html(agents: &[KnownAgent], signer_host: &str) -> String {
    let option = |a: &KnownAgent| {
        let hostport = a.origin().trim_start_matches("https://").to_string();
        let label = match &a.name {
            Some(n) => format!("{n} — {hostport}"),
            None => hostport,
        };
        format!(
            "<option value=\"{}\" data-local=\"{}\" data-name=\"{}\"{}>{}</option>",
            html_escape(&a.origin()),
            a.local,
            html_escape(a.name.as_deref().unwrap_or("")),
            if std::ptr::eq(a, &agents[0]) { " selected" } else { "" },
            html_escape(&label)
        )
    };
    let group = |label: String, pick: &dyn Fn(&KnownAgent) -> bool| {
        let items: String = agents.iter().filter(|a| pick(a)).map(option).collect();
        if items.is_empty() {
            String::new()
        } else {
            format!("<optgroup label=\"{}\">{items}</optgroup>", html_escape(&label))
        }
    };
    [
        group(format!("This machine · {signer_host}"), &|a| a.local),
        group("config.toml".into(), &|a| !a.local && a.source == Source::Config),
        group("Your agents".into(), &|a| !a.local && a.source == Source::User),
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> url::Url {
        normalize(s).unwrap()
    }

    #[test]
    fn user_file_parses_and_normalizes() {
        let agents = parse_user_file(
            r#"
            [[agents]]
            url = "https://db01.example.com:10022/some/path?x=1"
            name = " db01 "

            [[agents]]
            url = "https://web01.example.com:10022"
            "#,
        )
        .unwrap();
        assert_eq!(agents[0].0.as_str(), "https://db01.example.com:10022/");
        assert_eq!(agents[0].1.as_deref(), Some("db01"));
        assert_eq!(agents[1].1, None);
    }

    #[test]
    fn user_file_rejects_http_and_unknown_keys() {
        assert!(parse_user_file("[[agents]]\nurl = \"http://db01:10022\"").is_err());
        assert!(parse_user_file("[[agents]]\nurl = \"https://db01:10022\"\nca = \"x\"").is_err());
        assert!(parse_user_file("").unwrap().is_empty());
    }

    #[test]
    fn merge_dedupes_and_marks_local() {
        let agents = merge(
            vec![(u("https://localhost:10022"), None), (u("https://db01:10022"), None)],
            vec![
                (u("https://db01:10022/"), Some("primary db".into())),
                (u("https://127.0.0.1:10030"), Some("scratch".into())),
                (u("https://web01:10022"), None),
            ],
        );
        let summary: Vec<_> = agents
            .iter()
            .map(|a| (a.origin(), a.name.clone(), a.source, a.local))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("https://localhost:10022".into(), None, Source::Config, true),
                ("https://db01:10022".into(), Some("primary db".into()), Source::Config, false),
                ("https://127.0.0.1:10030".into(), Some("scratch".into()), Source::User, true),
                ("https://web01:10022".into(), None, Source::User, false),
            ]
        );
    }

    #[test]
    fn options_group_and_escape() {
        let agents = merge(
            vec![(u("https://localhost:10022"), None)],
            vec![(u("https://web01:10022"), Some("<web>".into()))],
        );
        let html = options_html(&agents, "desk");
        assert!(html.starts_with("<optgroup label=\"This machine · desk\">"));
        assert!(html.contains("value=\"https://localhost:10022\" data-local=\"true\" data-name=\"\" selected"));
        assert!(html.contains("<optgroup label=\"Your agents\">"));
        assert!(html.contains("&lt;web&gt; — web01:10022"));
        assert!(!html.contains("config.toml"), "empty groups are left out");
    }
}
