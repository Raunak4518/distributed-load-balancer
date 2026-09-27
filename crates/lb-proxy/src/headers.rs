use hyper::header::{HeaderName, HeaderValue};
use hyper::HeaderMap;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct HeaderEdits {
    set: Vec<(HeaderName, HeaderValue)>,
    remove: Vec<HeaderName>,
}

impl HeaderEdits {
    pub fn new(set: &BTreeMap<String, String>, remove: &[String]) -> Self {
        HeaderEdits {
            set: set
                .iter()
                .filter_map(|(name, value)| {
                    Some((
                        HeaderName::from_bytes(name.as_bytes()).ok()?,
                        HeaderValue::from_str(value).ok()?,
                    ))
                })
                .collect(),
            remove: remove
                .iter()
                .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
                .collect(),
        }
    }

    pub fn apply(&self, headers: &mut HeaderMap) {
        for name in &self.remove {
            headers.remove(name);
        }
        for (name, value) in &self.set {
            headers.insert(name.clone(), value.clone());
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct HeaderRewrite {
    pub request: HeaderEdits,
    pub response: HeaderEdits,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edits(set: &[(&str, &str)], remove: &[&str]) -> HeaderEdits {
        HeaderEdits::new(
            &set.iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
            &remove.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
        )
    }

    #[test]
    fn set_replaces_every_existing_value_and_remove_drops_them_all() {
        let mut h = HeaderMap::new();
        h.append("x-env", HeaderValue::from_static("dev"));
        h.append("x-env", HeaderValue::from_static("test"));
        h.append("x-debug", HeaderValue::from_static("1"));
        h.append("x-debug", HeaderValue::from_static("2"));
        edits(&[("X-Env", "prod")], &["x-debug"]).apply(&mut h);
        assert_eq!(
            h.get_all("x-env").iter().collect::<Vec<_>>(),
            vec![&HeaderValue::from_static("prod")]
        );
        assert!(!h.contains_key("x-debug"));
    }

    #[test]
    fn a_header_both_removed_and_set_ends_up_set() {
        let mut h = HeaderMap::new();
        h.insert("server", HeaderValue::from_static("backend/1.0"));
        edits(&[("server", "lb")], &["server"]).apply(&mut h);
        assert_eq!(h["server"], "lb");
    }
}
