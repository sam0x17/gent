use gent_crypto::{
    configuration_log::WriteCapability,
    web_failover::{sign, verify},
};
use gent_protocol::{configuration_log::Head, web_failover::Admission};

#[test]
fn admission_is_bound_to_current_authority_native_carrier_web_node_and_body() {
    let key = WriteCapability::generate().unwrap();
    let head = Head {
        sequence: 10,
        digest: [3; 32],
        write_key: key.public_key(),
    };
    let proof = sign(
        &key.secret(),
        Admission {
            version: 1,
            cluster: uuid::Uuid::new_v4().to_string(),
            node: uuid::Uuid::new_v4().to_string(),
            web: uuid::Uuid::new_v4().to_string(),
            head: head.clone(),
            expires_at: 1045,
            body_hash: [7; 32],
            signature: vec![],
        },
    )
    .unwrap();
    verify(&proof, &head, 1000).unwrap();
    assert!(verify(&proof, &head, 1045).is_err());
    assert!(verify(&proof, &head, 980).is_err());
    for field in ["node", "web", "cluster", "body"] {
        let mut changed = proof.clone();
        match field {
            "node" => changed.node = uuid::Uuid::new_v4().to_string(),
            "web" => changed.web = uuid::Uuid::new_v4().to_string(),
            "cluster" => changed.cluster = uuid::Uuid::new_v4().to_string(),
            _ => changed.body_hash[0] ^= 1,
        }
        assert!(verify(&changed, &head, 1000).is_err());
    }
    let mut advanced = head;
    advanced.sequence += 1;
    assert!(verify(&proof, &advanced, 1000).is_err());
}
