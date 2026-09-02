//! Direct Database Account & Proxy Resolver with Moka Cache and PG LISTEN/NOTIFY.
//!
//! Features:
//! 1. `moka::future::Cache` for high-throughput, concurrent in-memory caching.
//! 2. Real-time cache invalidation and updates via PostgreSQL `LISTEN sub2api_account_events`.
//! 3. Automatic installation of non-intrusive DB notification triggers on startup.
//! 4. Background auto-reconnecting listener loop.

use moka::future::Cache;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountProfile {
    pub account_id: i64,
    pub proxy_url: Option<String>,
    pub fingerprint_seed: String,
    pub custom_installation_id: Option<String>,
}

fn build_proxy_url(
    protocol: &str,
    host: &str,
    port: i32,
    username: Option<&str>,
    password: Option<&str>,
) -> Option<String> {
    let mut scheme = protocol.trim().to_ascii_lowercase();
    if scheme == "socks5" {
        scheme = "socks5h".to_string();
    }
    if !matches!(scheme.as_str(), "http" | "https" | "socks5h") {
        return None;
    }

    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    let port = u16::try_from(port).ok().filter(|port| *port != 0)?;

    let mut url = reqwest::Url::parse(&format!("{scheme}://localhost")).ok()?;
    let unbracketed_host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = unbracketed_host.parse::<IpAddr>() {
        url.set_ip_host(ip).ok()?;
    } else {
        url.set_host(Some(host)).ok()?;
    }
    url.set_port(Some(port)).ok()?;

    if let Some(username) = username.filter(|value| !value.is_empty()) {
        url.set_username(username).ok()?;
        if let Some(password) = password.filter(|value| !value.is_empty()) {
            url.set_password(Some(password)).ok()?;
        }
    }

    Some(url.to_string())
}

#[derive(Clone)]
pub struct DbProxyResolver {
    db_url: Option<String>,
    client: Arc<Mutex<Option<tokio_postgres::Client>>>,
    cache: Cache<i64, Option<AccountProfile>>,
}

impl DbProxyResolver {
    pub fn new(db_url: Option<String>) -> Self {
        let db_url = db_url.and_then(|u| {
            let trimmed = u.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });

        // Build Moka async cache with 10,000 capacity and 10 minute TTL
        let cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(600))
            .build();

        let resolver = Self {
            db_url: db_url.clone(),
            client: Arc::new(Mutex::new(None)),
            cache,
        };

        if let Some(ref url) = db_url {
            let listener_resolver = resolver.clone();
            let url_clone = url.clone();
            tokio::spawn(async move {
                listener_resolver.run_notification_listener(url_clone).await;
            });
        }

        resolver
    }

    pub fn is_configured(&self) -> bool {
        self.db_url.is_some()
    }

    /// Resolve the account profile (proxy + fingerprint settings) for the given account_id.
    pub async fn resolve_account_profile(
        &self,
        account_id: i64,
    ) -> Result<Option<AccountProfile>, String> {
        if self.db_url.is_none() {
            return Ok(None);
        }

        // 1. Fast path: Moka async cache get
        if let Some(cached) = self.cache.get(&account_id).await {
            return Ok(cached);
        }

        // 2. Query the database
        let db_url = self.db_url.as_ref().unwrap();
        let mut client_guard = self.client.lock().await;

        let needs_connect = match client_guard.as_ref() {
            Some(c) => c.is_closed(),
            None => true,
        };

        if needs_connect {
            let (new_client, connection) = tokio_postgres::connect(db_url, tokio_postgres::NoTls)
                .await
                .map_err(|e| format!("db connect failed: {e}"))?;
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    tracing::warn!("sidecar db connection error: {e}");
                }
            });
            *client_guard = Some(new_client);
        }

        let client = client_guard.as_ref().unwrap();
        let query = "SELECT a.id, a.extra, p.protocol, p.host, p.port, p.username, p.password \
                     FROM accounts a \
                     LEFT JOIN proxies p ON a.proxy_id = p.id AND p.deleted_at IS NULL AND p.status = 'active' \
                     WHERE a.id = $1";

        let row_opt = client
            .query_opt(query, &[&account_id])
            .await
            .map_err(|e| format!("db query account profile: {e}"))?;

        let profile_opt = row_opt.map(|row| {
            let acc_id: i64 = row.get(0);
            let extra_val: Option<serde_json::Value> = row.get(1);

            let mut fingerprint_seed = format!("account:{acc_id}");
            let mut custom_installation_id = None;

            if let Some(extra) = extra_val {
                if let Some(obj) = extra.as_object() {
                    if let Some(seed_str) =
                        obj.get("codex_fingerprint_seed").and_then(|v| v.as_str())
                    {
                        if !seed_str.trim().is_empty() {
                            fingerprint_seed = seed_str.trim().to_string();
                        }
                    } else if let Some(seed_str) = obj.get("device_seed").and_then(|v| v.as_str()) {
                        if !seed_str.trim().is_empty() {
                            fingerprint_seed = seed_str.trim().to_string();
                        }
                    }
                    if let Some(inst_str) = obj
                        .get("installation_id")
                        .or_else(|| obj.get("openai_device_id"))
                        .or_else(|| obj.get("device_id"))
                        .and_then(|v| v.as_str())
                    {
                        if !inst_str.trim().is_empty() {
                            custom_installation_id = Some(inst_str.trim().to_string());
                        }
                    }
                }
            }

            let protocol_opt: Option<String> = row.get(2);
            let host_opt: Option<String> = row.get(3);
            let port_opt: Option<i32> = row.get(4);
            let username_opt: Option<String> = row.get(5);
            let password_opt: Option<String> = row.get(6);

            let proxy_url = match (protocol_opt.as_deref(), host_opt.as_deref(), port_opt) {
                (Some(protocol), Some(host), Some(port)) => build_proxy_url(
                    protocol,
                    host,
                    port,
                    username_opt.as_deref(),
                    password_opt.as_deref(),
                ),
                _ => None,
            };

            AccountProfile {
                account_id: acc_id,
                proxy_url,
                fingerprint_seed,
                custom_installation_id,
            }
        });

        // 3. Populate Moka cache
        self.cache.insert(account_id, profile_opt.clone()).await;

        Ok(profile_opt)
    }

    /// Resolve only the proxy URL for the given account_id.
    #[allow(dead_code)]
    pub async fn resolve_proxy_for_account(
        &self,
        account_id: i64,
    ) -> Result<Option<String>, String> {
        let profile_opt = self.resolve_account_profile(account_id).await?;
        Ok(profile_opt.and_then(|p| p.proxy_url))
    }

    /// Background task that listens on `sub2api_account_events` and invalidates Moka cache on changes.
    async fn run_notification_listener(&self, db_url: String) {
        loop {
            match tokio_postgres::connect(&db_url, tokio_postgres::NoTls).await {
                Ok((client, mut connection)) => {
                    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

                    // Drive connection network I/O in the background so client calls don't deadlock
                    let conn_handle = tokio::spawn(async move {
                        use futures::StreamExt;
                        let stream =
                            futures::stream::poll_fn(move |cx| connection.poll_message(cx));
                        tokio::pin!(stream);
                        while let Some(msg_res) = stream.next().await {
                            match msg_res {
                                Ok(tokio_postgres::AsyncMessage::Notification(notif)) => {
                                    if tx.send(notif).is_err() {
                                        break;
                                    }
                                }
                                Ok(_) => {}
                                Err(e) => {
                                    tracing::warn!("postgres connection stream error: {e}");
                                    break;
                                }
                            }
                        }
                    });

                    // Try setting up notification triggers if DB permissions allow
                    let setup_triggers_sql = r#"
                    CREATE OR REPLACE FUNCTION notify_sub2api_account_change() RETURNS trigger AS $$
                    BEGIN
                      IF TG_OP = 'DELETE' THEN
                        PERFORM pg_notify('sub2api_account_events', json_build_object('event', 'delete', 'account_id', OLD.id)::text);
                        RETURN OLD;
                      ELSE
                        PERFORM pg_notify('sub2api_account_events', json_build_object('event', 'update', 'account_id', NEW.id)::text);
                        RETURN NEW;
                      END IF;
                    END;
                    $$ LANGUAGE plpgsql;

                    DO $$
                    BEGIN
                      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_sub2api_account_notify') THEN
                        CREATE TRIGGER trg_sub2api_account_notify
                        AFTER INSERT OR UPDATE OR DELETE ON accounts
                        FOR EACH ROW EXECUTE FUNCTION notify_sub2api_account_change();
                      END IF;
                    END;
                    $$;

                    CREATE OR REPLACE FUNCTION notify_sub2api_proxy_change() RETURNS trigger AS $$
                    BEGIN
                      PERFORM pg_notify('sub2api_account_events', json_build_object('event', 'reload')::text);
                      RETURN NULL;
                    END;
                    $$ LANGUAGE plpgsql;

                    DO $$
                    BEGIN
                      IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_sub2api_proxy_notify') THEN
                        CREATE TRIGGER trg_sub2api_proxy_notify
                        AFTER INSERT OR UPDATE OR DELETE ON proxies
                        FOR EACH ROW EXECUTE FUNCTION notify_sub2api_proxy_change();
                      END IF;
                    END;
                    $$;
                    "#;

                    if let Err(e) = client.batch_execute(setup_triggers_sql).await {
                        tracing::debug!(
                            "skipping auto-trigger setup (may lack DDL permissions): {e}"
                        );
                    }

                    if let Err(e) = client.execute("LISTEN sub2api_account_events", &[]).await {
                        tracing::warn!("failed to listen on sub2api_account_events: {e}");
                        conn_handle.abort();
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    }
                    tracing::info!(
                        "listening for real-time account cache invalidations on 'sub2api_account_events'"
                    );

                    let cache_ref = self.cache.clone();
                    while let Some(notif) = rx.recv().await {
                        let payload = notif.payload();
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(payload) {
                            if let Some(event) = val.get("event").and_then(|v| v.as_str()) {
                                match event {
                                    "update" | "delete" => {
                                        if let Some(acc_id) =
                                            val.get("account_id").and_then(|v| v.as_i64())
                                        {
                                            tracing::info!(account_id = acc_id, event, "invalidating moka account cache via DB notification");
                                            cache_ref.invalidate(&acc_id).await;
                                        }
                                    }
                                    "reload" => {
                                        tracing::info!(
                                            "reloading all account moka caches via DB proxy reload notification"
                                        );
                                        cache_ref.invalidate_all();
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    conn_handle.abort();
                }
                Err(e) => {
                    tracing::warn!("notification listener connect failed: {e}");
                }
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unconfigured_db_returns_none() {
        let resolver = DbProxyResolver::new(None);
        assert!(!resolver.is_configured());
        let result = resolver.resolve_account_profile(123).await;
        assert_eq!(result, Ok(None));

        let resolver_empty = DbProxyResolver::new(Some("   ".into()));
        assert!(!resolver_empty.is_configured());
    }

    #[tokio::test]
    async fn moka_cache_hit_and_invalidation() {
        let resolver = DbProxyResolver::new(Some("postgres://invalid".into()));
        assert!(resolver.is_configured());

        let profile = AccountProfile {
            account_id: 42,
            proxy_url: Some("socks5h://127.0.0.1:1080".into()),
            fingerprint_seed: "seed_42".into(),
            custom_installation_id: None,
        };

        // Pre-fill Moka cache
        resolver.cache.insert(42, Some(profile.clone())).await;

        // Resolving hits Moka cache without connecting to invalid DB URL
        let resolved = resolver.resolve_account_profile(42).await;
        assert_eq!(resolved, Ok(Some(profile)));

        let proxy = resolver.resolve_proxy_for_account(42).await;
        assert_eq!(proxy, Ok(Some("socks5h://127.0.0.1:1080".into())));

        // Invalidate key in Moka cache
        resolver.cache.invalidate(&42).await;
        assert!(resolver.cache.get(&42).await.is_none());
    }

    #[test]
    fn proxy_url_builder_handles_ipv6_and_reserved_credentials() {
        let raw = build_proxy_url(
            "socks5h",
            "::1",
            1080,
            Some("user@name"),
            Some("p/a:ss@word"),
        )
        .expect("valid proxy URL");
        let parsed = reqwest::Url::parse(&raw).expect("parse proxy URL");

        assert_eq!(parsed.scheme(), "socks5h");
        assert_eq!(parsed.port(), Some(1080));
        assert!(raw.contains("@[::1]:1080"), "{raw}");
        assert!(raw.contains("user%40name"), "{raw}");
        assert!(!raw.contains("user@name"), "{raw}");
    }

    #[test]
    fn proxy_url_builder_upgrades_socks5_to_socks5h() {
        let raw = build_proxy_url("socks5", "127.0.0.1", 1080, None, None).expect("valid proxy URL");
        assert_eq!(raw, "socks5h://127.0.0.1:1080");
    }

    #[test]
    fn proxy_url_builder_rejects_invalid_fields() {
        assert!(build_proxy_url("ftp", "127.0.0.1", 21, None, None).is_none());
        assert!(build_proxy_url("http", "", 8080, None, None).is_none());
        assert!(build_proxy_url("http", "127.0.0.1", 0, None, None).is_none());
        assert!(build_proxy_url("http", "127.0.0.1", 70_000, None, None).is_none());
    }
}
