use super::*;

#[test]
fn named_codes_bind_both_labels_and_reject_relabeling_or_downgrading() {
    let code = Code::named("personal", "sam-laptop").unwrap();
    let text = code.expose();
    assert!(text.starts_with("gent2-personal.sam-laptop."));
    let restored = Code::parse(&text).unwrap();
    assert_eq!(restored.names(), Some(("personal", "sam-laptop")));
    let sealed = code
        .seal("account", "cluster-id", 42, true, b"invitation")
        .unwrap();
    assert_eq!(
        &*restored
            .open("account", "cluster-id", 42, true, &sealed)
            .unwrap(),
        b"invitation"
    );
    for changed in [
        text.replace("personal", "work"),
        text.replace("sam-laptop", "server"),
        format!("gent1-{}", text.rsplit('.').next().unwrap()),
    ] {
        let changed = Code::parse(&changed).unwrap();
        assert_ne!(changed.id(), code.id());
        assert!(
            changed
                .open("account", "cluster-id", 42, true, &sealed)
                .is_err()
        );
    }
}

#[test]
fn names_round_trip_unicode_and_shell_characters_without_ambiguous_delimiters() {
    for (cluster, node) in [
        ("My cluster", "laptop.v2"),
        ("été", "$(secret);'\"`\\"),
        (&"a".repeat(128), &"é".repeat(64)),
    ] {
        let code = Code::named(cluster, node).unwrap();
        let text = code.expose();
        assert!(
            text.bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.%".contains(&c))
        );
        assert_eq!(Code::parse(&text).unwrap().names(), Some((cluster, node)));
        assert!(text.len() <= 1024);
    }
    for value in [
        "gent2-a.b.secret",
        "gent2-a..secret",
        "gent2-%61.b.secret",
        "gent2-%FF.b.secret",
        "gent2-%0A.b.secret",
    ] {
        assert!(Code::parse(value).is_err());
    }
}
