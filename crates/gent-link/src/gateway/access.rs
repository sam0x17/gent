use serde_json::{Value, json};

#[derive(Clone, Copy, Default)]
pub(crate) enum AccessRoute {
    #[default]
    Direct,
    Hosted,
}

impl AccessRoute {
    pub(crate) fn disclosure(self) -> &'static str {
        match self {
            Self::Direct => {
                "Remote route: user-controlled gateway. Plaintext tool calls terminate on the owner's node and at the model provider. Gent's central relay receives encrypted node traffic. This is not encryption against the model provider."
            }
            Self::Hosted => {
                "Remote route: Gent-hosted web bridge. The model provider, Gent's hosted endpoint (including Cloudflare), and your gateway node can read connector messages and files, even when you use a phone. This connector path is not end-to-end encrypted. Other node-to-node messages remain encrypted."
            }
        }
    }

    pub(crate) fn summary(self) -> Value {
        let (mode, endpoints) = match self {
            Self::Direct => (
                "user_controlled_gateway",
                vec!["model_provider", "user_node"],
            ),
            Self::Hosted => (
                "hosted_bridge",
                vec![
                    "model_provider",
                    "gent_hosted_endpoint",
                    "cloudflare",
                    "user_node",
                ],
            ),
        };
        json!({"mode":mode,"plaintext_endpoints":endpoints,"gent_relay":"encrypted_node_traffic_only",
            "disclosure":self.disclosure(),"file_access":"listed remote file tools; no local filesystem"})
    }
}
