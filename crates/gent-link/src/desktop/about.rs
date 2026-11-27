//! Public release information is fetched only when the desktop opens About.
use crate::build_info::{self, Build};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests;

const REPOSITORY: &str = "https://github.com/sam0x17/gent";
const LATEST: &str = "https://api.github.com/repos/sam0x17/gent/releases/latest";
const BUNDLED_NOTES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/releases/",
    env!("CARGO_PKG_VERSION"),
    ".md"
));
const MAX_RESPONSE: usize = 256 * 1024;

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Request {
    About,
}

#[derive(Serialize)]
struct Release {
    version: String,
    url: String,
    notes: String,
    #[serde(skip)]
    target: Option<String>,
}

impl Release {
    fn bundled() -> Self {
        let version = env!("CARGO_PKG_VERSION");
        Self {
            version: version.into(),
            url: format!("{REPOSITORY}/releases/tag/v{version}"),
            notes: BUNDLED_NOTES.trim().into(),
            target: None,
        }
    }

    fn page(&self, build: &Build) -> Value {
        let revision_url = build_info::valid_commit(&build.commit).then(|| {
            if !build.dirty && self.target.as_deref() == Some(&build.commit) {
                self.url.clone()
            } else {
                format!("{REPOSITORY}/commit/{}", build.commit)
            }
        });
        json!({
            "page":"about", "title":"Gent",
            "detail":format!("Version {} · {}{}\nCopyright © 2026 DuroSoft LLC",build.version,
                build.commit.chars().take(12).collect::<String>(), if build.dirty {" (development)"} else {""}),
            "actions":[{"kind":"check_update","title":"Check for updates"}],
            "version":build.version, "revision":build.commit, "revision_url":revision_url,
            "latest_release":self,
        })
    }
}

#[derive(Deserialize)]
struct GitHubRelease {
    draft: bool,
    prerelease: bool,
    tag_name: String,
    html_url: String,
    body: String,
    target_commitish: Option<String>,
}

impl GitHubRelease {
    fn published(self) -> Option<Release> {
        let version = self.tag_name.strip_prefix('v')?;
        let parts: [&str; 3] = version.splitn(3, '.').collect::<Vec<_>>().try_into().ok()?;
        if self.draft
            || self.prerelease
            || parts.iter().any(|p| {
                p.is_empty()
                    || (p.len() > 1 && p.starts_with('0'))
                    || !p.bytes().all(|b| b.is_ascii_digit())
            })
            || self.html_url != format!("{REPOSITORY}/releases/tag/{}", self.tag_name)
        {
            return None;
        }
        const END: &str = "<!-- gent-release-notes:end -->";
        let marked = self.body.lines().any(|line| line.trim() == END);
        let notes = self
            .body
            .lines()
            .take_while(|line| {
                let line = line.trim();
                if marked {
                    line != END
                } else {
                    !line.starts_with("**Full Changelog**:") && line != "### Published crates"
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        let notes = notes.trim();
        if notes.is_empty() {
            return None;
        }
        Some(Release {
            version: version.into(),
            url: self.html_url,
            notes: notes.into(),
            target: self
                .target_commitish
                .filter(|sha| build_info::valid_commit(sha)),
        })
    }
}

async fn fetch(endpoint: &str) -> Option<Release> {
    let client = reqwest::Client::builder()
        .user_agent(concat!("Gent-Desktop/", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(2))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    let mut response = client
        .get(endpoint)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .ok()?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if chunk.len() > MAX_RESPONSE - body.len() {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice::<GitHubRelease>(&body)
        .ok()?
        .published()
}

#[derive(Default)]
pub(super) struct Cache {
    release: Option<Release>,
    retry_at: Option<Instant>,
}

impl Cache {
    async fn resolve(&mut self, endpoint: &str) -> &Release {
        if self.retry_at.is_none_or(|at| Instant::now() >= at) {
            let ttl = if let Some(latest) = fetch(endpoint).await {
                self.release = Some(latest);
                3600
            } else {
                300
            };
            self.retry_at = Some(Instant::now() + Duration::from_secs(ttl));
        }
        self.release.get_or_insert_with(Release::bundled)
    }

    pub(super) async fn load(mut self) -> (Self, Value) {
        let page = self.resolve(LATEST).await.page(&build_info::current());
        (self, page)
    }
}
