//! Crawl frontier: pending queue + visited set with depth and scope limits.

use super::normalization::canonicalize;
use std::collections::{HashSet, VecDeque};

/// One queued URL with its crawl depth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontierItem {
    pub url: String,
    pub depth: u32,
}

#[derive(Debug, Clone)]
pub struct FrontierConfig {
    pub max_depth: u32,
    pub max_urls: usize,
}

impl Default for FrontierConfig {
    fn default() -> Self {
        Self {
            max_depth: 3,
            max_urls: 1000,
        }
    }
}

/// Breadth-first frontier with deduplication and hard limits.
pub struct CrawlFrontier {
    pending: VecDeque<FrontierItem>,
    visited: HashSet<String>,
    config: FrontierConfig,
    enqueued_total: usize,
}

impl CrawlFrontier {
    pub fn new(config: FrontierConfig) -> Self {
        Self {
            pending: VecDeque::new(),
            visited: HashSet::new(),
            config,
            enqueued_total: 0,
        }
    }

    /// Seed the frontier with a starting URL at depth 0.
    pub fn seed(&mut self, url: &str) {
        if let Some(canon) = canonicalize(url) {
            if self.visited.insert(canon.clone()) {
                self.pending.push_back(FrontierItem { url: canon, depth: 0 });
                self.enqueued_total += 1;
            }
        }
    }

    /// Add discovered links at `depth`, respecting depth and URL caps.
    /// Returns how many were actually enqueued.
    pub fn add_links<'a, I: IntoIterator<Item = &'a str>>(&mut self, links: I, depth: u32) -> usize {
        if depth > self.config.max_depth {
            return 0;
        }
        let mut added = 0;
        for link in links {
            if self.enqueued_total >= self.config.max_urls {
                break;
            }
            if let Some(canon) = canonicalize(link) {
                if self.visited.insert(canon.clone()) {
                    self.pending.push_back(FrontierItem { url: canon, depth });
                    self.enqueued_total += 1;
                    added += 1;
                }
            }
        }
        added
    }

    pub fn next(&mut self) -> Option<FrontierItem> {
        self.pending.pop_front()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn visited_len(&self) -> usize {
        self.visited.len()
    }

    /// Whether a URL has already been seen (without adding it).
    pub fn is_visited(&self, url: &str) -> bool {
        canonicalize(url)
            .map(|c| self.visited.contains(&c))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_then_next_is_fifo() {
        let mut f = CrawlFrontier::new(FrontierConfig::default());
        f.seed("https://example.com/");
        assert_eq!(f.next().unwrap().url, "https://example.com/");
        assert!(f.is_empty());
    }

    #[test]
    fn duplicate_links_not_requeued() {
        let mut f = CrawlFrontier::new(FrontierConfig::default());
        f.seed("https://example.com/");
        let added = f.add_links(["https://example.com/a", "https://example.com/a"], 1);
        assert_eq!(added, 1);
    }

    #[test]
    fn depth_limit_respected() {
        let mut f = CrawlFrontier::new(FrontierConfig {
            max_depth: 1,
            max_urls: 100,
        });
        f.seed("https://example.com/");
        assert_eq!(f.add_links(["https://example.com/deep"], 2), 0);
    }

    #[test]
    fn url_cap_respected() {
        let mut f = CrawlFrontier::new(FrontierConfig {
            max_depth: 5,
            max_urls: 2,
        });
        f.seed("https://example.com/");
        let added = f.add_links(
            ["https://example.com/a", "https://example.com/b", "https://example.com/c"],
            1,
        );
        assert_eq!(added, 1, "seed + 1 = cap of 2");
    }

    #[test]
    fn canonical_dedup_across_trailing_slash() {
        let mut f = CrawlFrontier::new(FrontierConfig::default());
        f.seed("https://example.com/a/");
        assert!(f.is_visited("https://example.com/a"));
        assert_eq!(f.add_links(["https://example.com/a"], 1), 0);
    }

    #[test]
    fn invalid_links_ignored() {
        let mut f = CrawlFrontier::new(FrontierConfig::default());
        f.seed("https://example.com/");
        assert_eq!(f.add_links(["not a url", ""], 1), 0);
    }
}
