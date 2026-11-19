use super::*;

#[test]
fn group_writable_host_configuration_survives_install_refresh_and_uninstall() {
    for host in [Host::Codex, Host::ClaudeCode] {
        let (_temp, layout, mut spec) = fixture(host);
        fs::set_permissions(&layout.directory, fs::Permissions::from_mode(0o2775)).unwrap();
        let original = if host == Host::Codex {
            "# user preferences\nmodel = \"example-model\"\n"
        } else {
            "{\"userPreference\":true}\n"
        };
        put(&layout.server, original);
        let mut configs = vec![layout.server.clone()];
        if let Some(settings) = &layout.settings {
            put(settings, "{\"userPreference\":true}\n");
            configs.push(settings.clone());
        }
        if host == Host::Codex {
            let settings = enable_ide(&layout, &mut spec);
            put(&settings, "{\"userPreference\":true}\n");
            configs.push(settings);
        } else {
            enable_claude(&mut spec);
        }
        for path in &configs {
            fs::set_permissions(path, fs::Permissions::from_mode(0o664)).unwrap();
        }
        for refresh in [false, true] {
            if refresh {
                spec.binary = spec.binary.with_file_name("gent-updated");
            }
            mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
            assert_eq!(inspect(&layout, &spec.home).unwrap()["state"], "configured");
            assert_eq!(fs::metadata(layout.record()).unwrap().mode() & 0o777, 0o600);
            for path in &configs {
                assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o664);
            }
        }
        mutate(&layout, &spec.home, None).unwrap();
        assert_eq!(inspect(&layout, &spec.home).unwrap()["state"], "absent");
        assert_eq!(
            fs::metadata(&layout.directory).unwrap().mode() & 0o7777,
            0o2775
        );
        for path in configs {
            assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o664);
            let text = get(&path);
            assert!(text.contains("userPreference") || text.contains("example-model"));
        }
    }
}

#[test]
fn world_writable_host_paths_and_group_writable_gent_records_still_fail() {
    let (_temp, layout, spec) = fixture(Host::Codex);
    put(&layout.server, "model = \"example-model\"\n");
    for (directory, file) in [(0o777, 0o664), (0o775, 0o666)] {
        fs::set_permissions(&layout.directory, fs::Permissions::from_mode(directory)).unwrap();
        fs::set_permissions(&layout.server, fs::Permissions::from_mode(file)).unwrap();
        assert!(mutate(&layout, &spec.home, Some(spec.clone())).is_err());
        assert_eq!(get(&layout.server), "model = \"example-model\"\n");
        assert!(!layout.record().exists());
    }
    fs::set_permissions(&layout.directory, fs::Permissions::from_mode(0o775)).unwrap();
    fs::set_permissions(&layout.server, fs::Permissions::from_mode(0o664)).unwrap();
    mutate(&layout, &spec.home, Some(spec.clone())).unwrap();
    let before = get(&layout.server);
    fs::set_permissions(layout.record(), fs::Permissions::from_mode(0o660)).unwrap();
    assert!(mutate(&layout, &spec.home, None).is_err());
    assert_eq!(get(&layout.server), before);
}
