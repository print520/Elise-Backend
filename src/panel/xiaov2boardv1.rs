use crate::panel::types::{NodeInfo, OnlineDeviceItem, TrafficItem, User};
use crate::panel::XiaoV2BoardClient;
use parking_lot::RwLock;
use reqwest::header::IF_NONE_MATCH;
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

type PanelError = Box<dyn std::error::Error + Send + Sync>;

pub const PANEL_TYPES: &[&str] = &["xiaov2boardv1", "xiaoboardv1", "xiaov2bv1"];

pub const SUPPORTED_NODE_TYPES: &str =
    "vmess, vless, trojan, shadowsocks, hysteria, hysteria2, tuic, anytls, mieru, naive";

pub fn is_panel_type(panel_type: &str) -> bool {
    PANEL_TYPES
        .iter()
        .any(|t| t.eq_ignore_ascii_case(panel_type.trim()))
}

/// Canonical Elise protocol name for a configured legacy UniProxy node type.
pub fn normalize_node_type(raw: &str) -> Option<&'static str> {
    Some(match raw.trim().to_ascii_lowercase().as_str() {
        "vmess" | "v2ray" => "vmess",
        "vless" => "vless",
        "trojan" => "trojan",
        "shadowsocks" | "ss" => "shadowsocks",
        "hysteria" | "hy" => "hysteria",
        "hysteria2" | "hy2" => "hysteria2",
        "tuic" => "tuic",
        "anytls" => "anytls",
        "mieru" => "mieru",
        "naive" | "naiveproxy" => "naive",
        _ => return None,
    })
}

/// The legacy controller stores Hysteria 1 and 2 in one table and reports the
/// generation through the `version` field of the config response.
fn query_node_type(node_type: &'static str) -> &'static str {
    if node_type == "hysteria2" {
        "hysteria"
    } else {
        node_type
    }
}

fn known_reason(message: &str) -> Option<&'static str> {
    match message.trim() {
        "token is null" => Some("token is null: configure the panel server token"),
        "token is error" => Some("token is error: check the panel server token"),
        "server is not exist" => {
            Some("server is not exist: check that node_id and node_type match a panel node")
        }
        _ => None,
    }
}

async fn status_error(context: &str, resp: reqwest::Response) -> PanelError {
    let status = resp.status();
    let reason = resp.json::<Value>().await.ok().and_then(|v| {
        v.get("message")
            .and_then(Value::as_str)
            .and_then(known_reason)
    });
    match reason {
        Some(reason) => format!("XiaoV2BoardV1 {context} returned status {status}: {reason}"),
        None => format!("XiaoV2BoardV1 {context} returned status {status}"),
    }
    .into()
}

/// Rewrites a legacy UniProxy config body into the v2node field layout that
/// `XiaoV2BoardClient::parse_v2_node_info` understands.
fn normalize_legacy_config(node_type: &'static str, data: &mut Value) {
    let Some(obj) = data.as_object_mut() else {
        return;
    };

    for key in ["server_port", "tls", "up_mbps", "down_mbps", "version"] {
        if let Some(n) = obj
            .get(key)
            .and_then(Value::as_str)
            .and_then(|s| s.trim().parse::<u64>().ok())
        {
            obj.insert(key.to_string(), json!(n));
        }
    }

    obj.insert("protocol".to_string(), json!(query_node_type(node_type)));

    match node_type {
        "hysteria" | "hysteria2" => {
            if !obj.contains_key("version") {
                let version = if node_type == "hysteria2" { 2 } else { 1 };
                obj.insert("version".to_string(), json!(version));
            }
            if obj.get("version").and_then(Value::as_u64) == Some(1) {
                if let Some(password) = obj.remove("obfs") {
                    if password.as_str().is_some_and(|p| !p.is_empty()) {
                        obj.insert("obfs_password".to_string(), password);
                    }
                }
            }
        }
        "shadowsocks" => {
            let obfs = obj.remove("obfs");
            let settings = obj.remove("obfs_settings");
            if obfs
                .as_ref()
                .and_then(Value::as_str)
                .is_some_and(|o| o.eq_ignore_ascii_case("http"))
            {
                let mut opts = serde_json::Map::new();
                opts.insert("obfs".to_string(), json!("http"));
                if let Some(host) = settings
                    .as_ref()
                    .and_then(|s| s.get("host"))
                    .and_then(Value::as_str)
                    .filter(|h| !h.trim().is_empty())
                {
                    opts.insert("obfs-host".to_string(), json!(host.trim()));
                }
                obj.insert("plugin".to_string(), json!("obfs"));
                obj.insert("plugin_opts".to_string(), Value::Object(opts));
            }
        }
        _ => {}
    }
}

/// Client for the original XiaoV2Board/V2Board `UniProxy` API, where the node
/// protocol is selected by the `node_type` query parameter instead of being
/// returned by the panel.
pub struct XiaoV2BoardV1Client {
    client: Client,
    base_url: String,
    token: String,
    node_types: HashMap<u32, &'static str>,
    cached_users: RwLock<HashMap<u32, Arc<tokio::sync::Mutex<(Option<String>, Vec<User>)>>>>,
}

impl XiaoV2BoardV1Client {
    pub fn new(base_url: String, token: String, node_types: HashMap<u32, String>) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            node_types: node_types
                .into_iter()
                .filter_map(|(id, raw)| normalize_node_type(&raw).map(|t| (id, t)))
                .collect(),
            cached_users: RwLock::new(HashMap::new()),
        }
    }

    fn node_type(&self, node_id: u32) -> Result<&'static str, PanelError> {
        self.node_types.get(&node_id).copied().ok_or_else(|| {
            format!(
                "XiaoV2BoardV1: node_type is not configured for node {node_id} \
                 (supported: {SUPPORTED_NODE_TYPES})"
            )
            .into()
        })
    }

    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        node_id: u32,
    ) -> Result<reqwest::RequestBuilder, PanelError> {
        let node_type = query_node_type(self.node_type(node_id)?);
        Ok(self
            .client
            .request(method, format!("{}{}", self.base_url, path))
            .query(&[
                ("node_type", node_type),
                ("node_id", &node_id.to_string()),
                ("token", &self.token),
            ]))
    }

    pub async fn get_node_info(&self, node_id: u32) -> Result<NodeInfo, PanelError> {
        let node_type = self.node_type(node_id)?;
        let resp = self
            .request(
                reqwest::Method::GET,
                "/api/v1/server/UniProxy/config",
                node_id,
            )?
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        if !resp.status().is_success() {
            return Err(status_error("config API", resp).await);
        }

        let mut val: Value = resp.json().await?;
        if val.get("status").and_then(Value::as_str) == Some("fail") {
            let reason = val
                .get("message")
                .and_then(Value::as_str)
                .and_then(known_reason)
                .unwrap_or("panel rejected the node configuration request");
            return Err(format!("XiaoV2BoardV1 config API: {reason}").into());
        }
        if val.get("data").is_some_and(Value::is_object) {
            val = val["data"].take();
        }

        normalize_legacy_config(node_type, &mut val);
        if !matches!(
            val.get("server_port").and_then(Value::as_u64),
            Some(1..=65535)
        ) {
            return Err("Invalid XiaoV2BoardV1 config: invalid server_port".into());
        }
        Ok(XiaoV2BoardClient::parse_v2_node_info(node_id, &val))
    }

    pub async fn get_users(&self, node_id: u32) -> Result<Vec<User>, PanelError> {
        let cache = self
            .cached_users
            .write()
            .entry(node_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new((None, Vec::new()))))
            .clone();
        let mut cache = cache.lock().await;
        let mut req = self.request(
            reqwest::Method::GET,
            "/api/v1/server/UniProxy/user",
            node_id,
        )?;
        if let Some(etag) = cache.0.as_ref() {
            req = req.header(IF_NONE_MATCH, etag);
        }

        let resp = req.send().await.map_err(reqwest::Error::without_url)?;

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            if cache.0.is_none() {
                return Err("Panel returned 304 without a cached ETag".into());
            }
            return Ok(cache.1.clone());
        }

        if !resp.status().is_success() {
            return Err(status_error("user sync", resp).await);
        }

        let new_etag = resp
            .headers()
            .get("ETag")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);

        let val: Value = resp.json().await?;
        let Some(user_list) = val
            .get("users")
            .or_else(|| val.get("data"))
            .and_then(|v| v.as_array())
        else {
            return Err("Panel user response has no users array".into());
        };

        let mut users = Vec::with_capacity(user_list.len());
        for item in user_list {
            users.push(User {
                id: item.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                uuid: item
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                speed_limit: crate::panel::types::speed_limit_bps(item.get("speed_limit"))?,
                device_limit: item
                    .get("device_limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32,
                username: item
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                password: item
                    .get("password")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                method: item
                    .get("method")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                port: item.get("port").and_then(|v| v.as_u64()).map(|v| v as u16),
                flow: item.get("flow").and_then(|v| v.as_str()).map(String::from),
            });
        }

        *cache = (new_etag, users.clone());
        Ok(users)
    }

    pub async fn report_traffic(
        &self,
        node_id: u32,
        traffic: Vec<TrafficItem>,
    ) -> Result<(), PanelError> {
        if traffic.is_empty() {
            return Ok(());
        }

        let mut payload: HashMap<String, [u64; 2]> = HashMap::with_capacity(traffic.len());
        for item in traffic {
            payload.insert(item.user_id.to_string(), [item.u, item.d]);
        }

        let resp = self
            .request(
                reqwest::Method::POST,
                "/api/v1/server/UniProxy/push",
                node_id,
            )?
            .json(&payload)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        if !resp.status().is_success() {
            return Err(status_error("traffic report", resp).await);
        }
        Ok(())
    }

    pub async fn report_online_devices(
        &self,
        node_id: u32,
        devices: Vec<OnlineDeviceItem>,
    ) -> Result<(), PanelError> {
        if devices.is_empty() {
            return Ok(());
        }

        let mut payload: HashMap<String, Vec<String>> = HashMap::with_capacity(devices.len());
        for item in devices {
            payload.insert(item.user_id.to_string(), item.ips);
        }

        let resp = self
            .request(
                reqwest::Method::POST,
                "/api/v1/server/UniProxy/alive",
                node_id,
            )?
            .json(&payload)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        if !resp.status().is_success() {
            return Err(status_error("online report", resp).await);
        }
        Ok(())
    }

    pub async fn get_user_alivelist(&self, node_id: u32) -> Result<HashMap<u32, u32>, PanelError> {
        let resp = self
            .request(
                reqwest::Method::GET,
                "/api/v1/server/UniProxy/alivelist",
                node_id,
            )?
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        if !resp.status().is_success() {
            return Err(status_error("alive list", resp).await);
        }
        let val: Value = resp.json().await?;

        let mut res = HashMap::new();
        if let Some(map) = val
            .get("alive")
            .or_else(|| val.get("data"))
            .or(Some(&val))
            .and_then(|v| v.as_object())
        {
            for (k, v) in map {
                if let (Ok(uid), Some(cnt)) = (k.parse::<u32>(), v.as_u64()) {
                    res.insert(uid, cnt as u32);
                }
            }
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    type Reply = (&'static str, &'static str, &'static str, String, Value);

    // Contract from the legacy V1 UniProxyController (config/user/push/alive/alivelist).
    async fn fixture(
        node_type: &str,
        expected_query_type: &'static str,
        replies: Vec<Reply>,
    ) -> (XiaoV2BoardV1Client, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token = "key+with&reserved=#?";
        let client = XiaoV2BoardV1Client::new(
            format!("http://{}", listener.local_addr().unwrap()),
            token.into(),
            HashMap::from([(7, node_type.to_string())]),
        );
        let server = tokio::spawn(async move {
            for (method, path, status, body, expected_body) in replies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(socket.read_u8().await.unwrap());
                }
                let headers = String::from_utf8(headers).unwrap();
                let mut line = headers.lines().next().unwrap().split_whitespace();
                assert_eq!(line.next().unwrap(), method);
                let url = reqwest::Url::parse(&format!("http://localhost{}", line.next().unwrap()))
                    .unwrap();
                assert_eq!(url.path(), path);
                let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
                assert_eq!(query.get("node_id").map(String::as_str), Some("7"));
                assert_eq!(
                    query.get("node_type").map(String::as_str),
                    Some(expected_query_type)
                );
                assert_eq!(query.get("token").map(String::as_str), Some(token));
                if method == "POST" {
                    let len = headers
                        .lines()
                        .find_map(|l| {
                            let (key, value) = l.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    let mut bytes = vec![0; len];
                    socket.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(
                        serde_json::from_slice::<Value>(&bytes).unwrap(),
                        expected_body
                    );
                }
                socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
        });
        (client, server)
    }

    async fn config(node_type: &str, query_type: &'static str, body: Value) -> NodeInfo {
        let (client, server) = fixture(
            node_type,
            query_type,
            vec![(
                "GET",
                "/api/v1/server/UniProxy/config",
                "200 OK",
                body.to_string(),
                Value::Null,
            )],
        )
        .await;
        let info = client.get_node_info(7).await.unwrap();
        server.await.unwrap();
        info
    }

    #[test]
    fn node_type_aliases() {
        assert_eq!(normalize_node_type("V2ray"), Some("vmess"));
        assert_eq!(normalize_node_type("ss"), Some("shadowsocks"));
        assert_eq!(normalize_node_type("hy2"), Some("hysteria2"));
        assert_eq!(normalize_node_type("Naive"), Some("naive"));
        assert_eq!(normalize_node_type("mieru"), Some("mieru"));
        assert_eq!(normalize_node_type("v2node"), None);
        assert!(is_panel_type("XiaoV2BoardV1"));
        assert!(is_panel_type("xiaoboardv1"));
        assert!(!is_panel_type("xiaov2board"));
    }

    #[tokio::test]
    async fn uniproxy_contract_covers_sync_traffic_and_online_ips() {
        let (client, server) = fixture("vless", "vless", vec![
            ("GET", "/api/v1/server/UniProxy/config", "200 OK", r#"{"server_port":"12345","network":"ws","networkSettings":{"path":"/ws","headers":{"Host":"cdn.example.com"}},"tls":"2","flow":"xtls-rprx-vision","tls_settings":{"server_name":"example.com","server_port":"443","private_key":"panel-private-key","short_id":"abcd"},"encryption":"none","base_config":{"push_interval":60,"pull_interval":60},"routes":[{"id":1,"match":["example.org"],"action":"block","action_value":null}]}"#.into(), Value::Null),
            ("GET", "/api/v1/server/UniProxy/user", "200 OK", r#"{"users":[{"id":12,"uuid":"test-uuid","speed_limit":8,"device_limit":3}]}"#.into(), Value::Null),
            ("POST", "/api/v1/server/UniProxy/push", "200 OK", r#"{"data":true}"#.into(), json!({"12":[104857600u64,524288000u64]})),
            ("POST", "/api/v1/server/UniProxy/alive", "200 OK", r#"{"data":true}"#.into(), json!({"12":["192.0.2.1","2001:db8::1"]})),
            ("GET", "/api/v1/server/UniProxy/alivelist", "200 OK", r#"{"alive":{"12":2}}"#.into(), Value::Null),
        ]).await;

        let info = client.get_node_info(7).await.unwrap();
        assert_eq!(info.node_type, "vless");
        assert_eq!(info.server_port, 12345);
        assert_eq!(info.tls, Some(2));
        assert_eq!(info.network.as_deref(), Some("ws"));
        assert_eq!(info.path.as_deref(), Some("/ws"));
        assert_eq!(info.host.as_deref(), Some("cdn.example.com"));
        assert_eq!(info.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(info.server_name.as_deref(), Some("example.com"));
        assert_eq!(info.short_ids, Some(vec!["abcd".to_string()]));
        assert_eq!(info.routes.as_ref().map(Vec::len), Some(1));

        let users = client.get_users(7).await.unwrap();
        assert_eq!(users[0].id, 12);
        assert_eq!(users[0].uuid, "test-uuid");
        assert_eq!(users[0].speed_limit, 1_000_000);
        assert_eq!(users[0].device_limit, 3);
        client
            .report_traffic(
                7,
                vec![TrafficItem {
                    user_id: 12,
                    u: 104857600,
                    d: 524288000,
                }],
            )
            .await
            .unwrap();
        client
            .report_online_devices(
                7,
                vec![OnlineDeviceItem {
                    user_id: 12,
                    ips: vec!["192.0.2.1".into(), "2001:db8::1".into()],
                }],
            )
            .await
            .unwrap();
        assert_eq!(
            client.get_user_alivelist(7).await.unwrap().get(&12),
            Some(&2)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn legacy_configs_map_to_elise_protocols() {
        let vmess = config(
            "v2ray",
            "vmess",
            json!({"server_port":10086,"network":"tcp","networkSettings":null,"tls":0}),
        )
        .await;
        assert_eq!(vmess.node_type, "vmess");
        assert_eq!(vmess.tls, Some(0));

        let trojan = config(
            "trojan",
            "trojan",
            json!({"host":"t.example.com","network":"grpc","networkSettings":{"serviceName":"svc"},"server_port":443,"server_name":"t.example.com"}),
        )
        .await;
        assert_eq!(trojan.node_type, "trojan");
        assert_eq!(trojan.network.as_deref(), Some("grpc"));
        assert_eq!(trojan.server_name.as_deref(), Some("t.example.com"));
        assert_eq!(trojan.network_settings.unwrap()["serviceName"], "svc");

        let ss = config(
            "shadowsocks",
            "shadowsocks",
            json!({"server_port":8388,"cipher":"2022-blake3-aes-128-gcm","obfs":"http","obfs_settings":{"host":"www.bing.com","path":"/"},"server_key":"c2VydmVyLWtleQ=="}),
        )
        .await;
        assert_eq!(ss.node_type, "shadowsocks");
        assert_eq!(ss.cipher.as_deref(), Some("2022-blake3-aes-128-gcm"));
        assert_eq!(ss.server_key.as_deref(), Some("c2VydmVyLWtleQ=="));
        assert_eq!(ss.plugin.as_deref(), Some("obfs"));
        assert_eq!(
            ss.plugin_opts,
            Some(json!({"obfs":"http","obfs-host":"www.bing.com"}))
        );
        assert_eq!(ss.obfs, None);
        crate::protocol::shadowsocks::transport::Transport::validate(&ss).unwrap();

        let plain_ss = config(
            "ss",
            "shadowsocks",
            json!({"server_port":8388,"cipher":"aes-128-gcm","obfs":null,"obfs_settings":null}),
        )
        .await;
        assert_eq!(plain_ss.plugin, None);

        let hy1 = config(
            "hysteria",
            "hysteria",
            json!({"version":1,"host":"h.example.com","server_port":443,"server_name":"h.example.com","up_mbps":100,"down_mbps":200,"obfs":"xplus-secret"}),
        )
        .await;
        assert_eq!(hy1.node_type, "hysteria");
        assert_eq!(hy1.version, Some(1));
        assert_eq!(hy1.obfs, None);
        assert_eq!(hy1.obfs_password.as_deref(), Some("xplus-secret"));
        assert_eq!(hy1.up_mbps, Some(100));

        let hy2 = config(
            "hysteria2",
            "hysteria",
            json!({"version":2,"host":"h.example.com","server_port":443,"server_name":"h.example.com","up_mbps":0,"down_mbps":0,"ignore_client_bandwidth":true,"obfs":"salamander","obfs-password":"salamander-secret"}),
        )
        .await;
        assert_eq!(hy2.node_type, "hysteria2");
        assert_eq!(hy2.obfs.as_deref(), Some("salamander"));
        assert_eq!(hy2.obfs_password.as_deref(), Some("salamander-secret"));

        let tuic = config(
            "tuic",
            "tuic",
            json!({"server_port":443,"server_name":"tuic.example.com","congestion_control":"bbr","zero_rtt_handshake":true}),
        )
        .await;
        assert_eq!(tuic.node_type, "tuic");
        assert_eq!(tuic.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(tuic.zero_rtt_handshake, Some(true));

        let anytls = config(
            "anytls",
            "anytls",
            json!({"server_port":443,"server_name":"a.example.com","padding_scheme":["stop=8","0=30-30"]}),
        )
        .await;
        assert_eq!(anytls.node_type, "anytls");
        assert_eq!(anytls.padding_scheme, Some(json!(["stop=8", "0=30-30"])));
    }

    // Shapes from MieruSettings::nodeConfig and the UniProxy user list of the
    // forked panel, which sends the user id as mieru username.
    #[tokio::test]
    async fn legacy_mieru_node_and_credentials() {
        let (client, server) = fixture("mieru", "mieru", vec![
            ("GET", "/api/v1/server/UniProxy/config", "200 OK", r#"{"listen_ip":"0.0.0.0","server_port":2012,"network":"tcp","network_settings":{"mtu":1400,"multiplexing":"MULTIPLEXING_LOW","handshake_mode":"HANDSHAKE_STANDARD","user_hint_is_mandatory":0},"port_bindings":[{"port":2012,"protocol":"TCP"}],"mtu":1400,"traffic_pattern":"","user_hint_is_mandatory":false,"base_config":{"push_interval":60,"pull_interval":60}}"#.into(), Value::Null),
            ("GET", "/api/v1/server/UniProxy/user", "200 OK", r#"{"users":[{"id":12,"uuid":"test-uuid","speed_limit":0,"device_limit":0,"username":"12","password":"test-uuid"}]}"#.into(), Value::Null),
        ]).await;

        let info = client.get_node_info(7).await.unwrap();
        assert_eq!(info.node_type, "mieru");
        assert_eq!(info.server_port, 2012);
        assert_eq!(info.transport.as_deref(), Some("TCP"));
        assert_eq!(info.listen_ip.as_deref(), Some("0.0.0.0"));

        let users = client.get_users(7).await.unwrap();
        assert_eq!(users[0].username.as_deref(), Some("12"));
        assert_eq!(users[0].password.as_deref(), Some("test-uuid"));
        let mieru = crate::protocol::mieru::crypto::MieruUser::from_panel_user(users[0].clone());
        assert_eq!(mieru.username, "12");
        assert_eq!(
            mieru.hashed_password,
            crate::protocol::mieru::crypto::hash_password(b"test-uuid", b"12")
        );
        server.await.unwrap();
    }

    // Shape from the forked panel's UniProxy `naive` case (NaiveSettings).
    #[tokio::test]
    async fn legacy_naive_node_uses_tls_and_panel_cert_files() {
        let info = config(
            "naive",
            "naive",
            json!({"listen_ip":"0.0.0.0","server_port":443,"network":"","tls":1,
                "tls_settings":{"server_name":"n.example.com","cert_mode":"file",
                    "cert_file":"/etc/elise/cert/n.crt","key_file":"/etc/elise/cert/n.key"},
                "quic_congestion_control":"bbr"}),
        )
        .await;
        assert_eq!(info.node_type, "naive");
        assert_eq!(info.tls, Some(1));
        assert_eq!(info.server_name.as_deref(), Some("n.example.com"));
        let tls = info.tls_settings.as_ref().unwrap();
        assert_eq!(tls["cert_file"], "/etc/elise/cert/n.crt");
        assert_eq!(tls["key_file"], "/etc/elise/cert/n.key");
    }

    #[tokio::test]
    async fn legacy_vless_reality_reaches_transport() {
        let pair = crate::security::generate_reality_keypair();
        let mut info = config(
            "vless",
            "vless",
            json!({"server_port":443,"network":"tcp","networkSettings":null,"tls":2,"flow":"xtls-rprx-vision",
                "tls_settings":{"server_name":"www.example.com","server_port":"443","public_key":pair.public_key,
                    "private_key":pair.private_key,"short_id":"01ab","allow_insecure":"0"},
                "encryption":null,"encryption_settings":null}),
        )
        .await;
        let dir = std::env::temp_dir().join(format!("elise-v1-{}", uuid::Uuid::new_v4()));
        let cfg = crate::config::NodeConfig {
            node_id: 7,
            ..Default::default()
        };
        cfg.prepare_node_info(&dir, &mut info).unwrap();
        let stream = crate::transport::types::StreamSettings::from_node_info(&info).unwrap();
        assert_eq!(
            stream.client_reality_profile.unwrap().public_key.as_deref(),
            Some(pair.public_key.as_str())
        );
    }

    #[test]
    fn global_config_resolves_node_types() {
        let cfg = crate::config::GlobalConfig::parse(
            "type=xiaov2boardv1\nnode_id=1,2,3\nnode_type=vless,trojan,ss\n[node_3]\nnode_type=hysteria2\n",
        );
        assert_eq!(cfg.panel_node_type_for(1).as_deref(), Some("vless"));
        assert_eq!(cfg.panel_node_type_for(2).as_deref(), Some("trojan"));
        assert_eq!(cfg.panel_node_type_for(3).as_deref(), Some("hysteria2"));
        assert_eq!(cfg.panel_node_type_for(9), None);

        let single = crate::config::GlobalConfig::parse("node_id=4,5\nnode_type=anytls\n");
        assert_eq!(single.panel_node_type_for(5).as_deref(), Some("anytls"));
    }

    #[test]
    fn global_config_rejects_missing_or_bad_node_types() {
        let dir = std::env::temp_dir().join(format!("elise-v1-cfg-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("elise.conf");
        for (content, expected) in [
            ("type=xiaov2boardv1\nnode_id=1\n", "requires node_type"),
            (
                "type=xiaov2boardv1\nnode_id=1\nnode_type=v2node\n",
                "unsupported node_type",
            ),
            (
                "type=xiaov2boardv1\nnode_id=1,2,3\nnode_type=vless,trojan\n",
                "one value per node",
            ),
        ] {
            std::fs::write(&path, content).unwrap();
            let error = crate::config::GlobalConfig::load_from_file(&path)
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
        }
        std::fs::write(
            &path,
            "type=xiaoboardv1\nnode_id=1,2\nnode_type=vmess\n[node_2]\nnode_type=tuic\n",
        )
        .unwrap();
        assert!(crate::config::GlobalConfig::load_from_file(&path).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn panel_errors_are_reported_without_leaking_bodies() {
        for (status, body, expected) in [
            (
                "500 Internal Server Error",
                r#"{"message":"token is error"}"#,
                "token is error",
            ),
            (
                "500 Internal Server Error",
                r#"{"message":"server is not exist"}"#,
                "node_type match",
            ),
            ("403 Forbidden", r#"{"message":"secret-value"}"#, "403"),
            ("200 OK", r#"{"server_port":0}"#, "invalid server_port"),
        ] {
            let (client, server) = fixture(
                "vmess",
                "vmess",
                vec![(
                    "GET",
                    "/api/v1/server/UniProxy/config",
                    status,
                    body.into(),
                    Value::Null,
                )],
            )
            .await;
            let error = client.get_node_info(7).await.unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
            assert!(!error.contains("secret-value"), "{error}");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn failed_reports_are_errors() {
        let (client, server) = fixture(
            "trojan",
            "trojan",
            vec![
                (
                    "POST",
                    "/api/v1/server/UniProxy/push",
                    "500 Internal Server Error",
                    "{}".into(),
                    json!({"12":[1,2]}),
                ),
                (
                    "POST",
                    "/api/v1/server/UniProxy/alive",
                    "500 Internal Server Error",
                    "{}".into(),
                    json!({"12":["192.0.2.1"]}),
                ),
                (
                    "GET",
                    "/api/v1/server/UniProxy/alivelist",
                    "500 Internal Server Error",
                    "{}".into(),
                    Value::Null,
                ),
            ],
        )
        .await;
        assert!(client
            .report_traffic(
                7,
                vec![TrafficItem {
                    user_id: 12,
                    u: 1,
                    d: 2
                }]
            )
            .await
            .is_err());
        assert!(client
            .report_online_devices(
                7,
                vec![OnlineDeviceItem {
                    user_id: 12,
                    ips: vec!["192.0.2.1".into()]
                }]
            )
            .await
            .is_err());
        assert!(client.get_user_alivelist(7).await.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn unconfigured_node_type_fails_without_request() {
        let client = XiaoV2BoardV1Client::new(
            "http://127.0.0.1:9".into(),
            "fixture".into(),
            HashMap::from([(1, "v2node".to_string())]),
        );
        let error = client.get_node_info(1).await.unwrap_err().to_string();
        assert!(error.contains("node_type is not configured"), "{error}");
        assert!(client.get_users(2).await.is_err());
    }
}
