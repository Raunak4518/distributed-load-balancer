use crate::service::ProxyBody;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode, Uri};

pub(crate) fn prefix_and_host_match(
    path_prefix: Option<&str>,
    host_rule: Option<&str>,
    path: &str,
    host: Option<&str>,
) -> bool {
    let path_ok = match path_prefix {
        None => true,
        Some(prefix) => path == prefix || path.starts_with(&format!("{prefix}/")),
    };
    let host_ok = match host_rule {
        None => true,
        Some(expected) => host.is_some_and(|h| h.eq_ignore_ascii_case(expected)),
    };
    path_ok && host_ok
}

#[derive(Clone, Debug)]
pub struct DirectResponse {
    pub path_prefix: Option<String>,
    pub host: Option<String>,
    pub status: StatusCode,
    pub body: Bytes,
    pub content_type: Option<HeaderValue>,
    pub redirect: Option<String>,
    pub keep_path: bool,
}

impl DirectResponse {
    pub fn matches(&self, path: &str, host: Option<&str>) -> bool {
        prefix_and_host_match(
            self.path_prefix.as_deref(),
            self.host.as_deref(),
            path,
            host,
        )
    }

    pub fn respond(&self, uri: &Uri) -> Response<ProxyBody> {
        let mut resp = Response::new(
            Full::new(self.body.clone())
                .map_err(|never| match never {})
                .boxed(),
        );
        *resp.status_mut() = self.status;
        let content_type = self.content_type.clone().or_else(|| {
            (!self.body.is_empty()).then(|| HeaderValue::from_static("text/plain; charset=utf-8"))
        });
        if let Some(content_type) = content_type {
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, content_type);
        }
        if let Some(location) = self.location(uri) {
            resp.headers_mut().insert(header::LOCATION, location);
        }
        resp
    }

    fn location(&self, uri: &Uri) -> Option<HeaderValue> {
        let base = self.redirect.as_deref()?;
        if !self.keep_path {
            return HeaderValue::from_str(base).ok();
        }
        let tail = uri.path_and_query().map_or("/", |pq| pq.as_str());
        HeaderValue::from_str(&format!("{}{tail}", base.trim_end_matches('/'))).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redirect(to: &str, keep_path: bool) -> DirectResponse {
        DirectResponse {
            path_prefix: None,
            host: None,
            status: StatusCode::PERMANENT_REDIRECT,
            body: Bytes::new(),
            content_type: None,
            redirect: Some(to.to_string()),
            keep_path,
        }
    }

    #[test]
    fn keep_path_appends_the_original_path_and_query() {
        let uri: Uri = "/docs/a?x=1".parse().unwrap();
        let resp = redirect("https://new.example/", true).respond(&uri);
        assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            resp.headers()[header::LOCATION],
            "https://new.example/docs/a?x=1"
        );
        let resp = redirect("https://new.example/", false).respond(&uri);
        assert_eq!(resp.headers()[header::LOCATION], "https://new.example/");
    }

    #[test]
    fn a_body_without_a_content_type_is_served_as_plain_text() {
        let page = DirectResponse {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: Bytes::from_static(b"down for maintenance"),
            redirect: None,
            ..redirect("", false)
        };
        let resp = page.respond(&"/".parse().unwrap());
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert!(!resp.headers().contains_key(header::LOCATION));
    }

    #[test]
    fn matching_uses_whole_path_segments_and_case_insensitive_hosts() {
        let rule = DirectResponse {
            path_prefix: Some("/old".into()),
            host: Some("A.example".into()),
            ..redirect("https://b.example", false)
        };
        assert!(rule.matches("/old", Some("a.EXAMPLE")));
        assert!(rule.matches("/old/page", Some("a.example")));
        assert!(!rule.matches("/older", Some("a.example")));
        assert!(!rule.matches("/old", Some("c.example")));
        assert!(!rule.matches("/old", None));
    }
}
