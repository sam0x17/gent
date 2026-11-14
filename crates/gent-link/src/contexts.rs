//! Resolve the default CLI context once. Daemons, MCP connections and installed
//! host hooks keep using their pinned physical directory across later switches.
use crate::managed_file::{self, Snapshot};
use anyhow::{Context, Result, ensure};
use gent_daemon::config::{self, Config, ContextProfile, Contexts};
use serde_json::{Value, json};
use std::{
    io::{self, BufRead, IsTerminal, Read, Write},
    path::{Path, PathBuf},
};
pub(crate) mod provision;

pub(crate) fn inspect(home: &Path) -> Result<Config> {
    gent_daemon::recovery::ensure_active(home)?;
    // Read-only checks: status and selection never create a missing directory.
    let metadata =
        std::fs::symlink_metadata(home).context("cluster profile directory is unavailable")?;
    use std::os::unix::fs::MetadataExt;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == rustix::process::geteuid().as_raw()
            && metadata.mode() & 0o077 == 0,
        "cluster profile directory must be private and owned by this user"
    );
    let snapshot = Snapshot::read(&config::path(home))?;
    snapshot.private()?;
    let cfg: Config = toml::from_str(
        snapshot
            .text
            .as_deref()
            .context("cluster profile configuration is missing")?,
    )?;
    cfg.validate_local()?;
    snapshot.verify()?;
    Ok(cfg)
}

fn registry(root: &Path, cfg: &Config) -> Result<Contexts> {
    let own = ContextProfile {
        home: root.into(),
        node_id: cfg.node.id.clone(),
    };
    let registry = cfg.contexts()?.unwrap_or_else(|| Contexts {
        version: 1,
        active_cluster: cfg.cluster.id.clone(),
        profiles: [(cfg.cluster.id.clone(), own.clone())].into(),
    });
    ensure!(
        registry.profiles.get(&cfg.cluster.id) == Some(&own),
        "profile registry belongs to another directory or node"
    );
    Ok(registry)
}

fn target(cluster: &str, profile: &ContextProfile) -> Result<Config> {
    ensure!(
        managed_file::normalize(&profile.home)? == profile.home,
        "cluster profile directory changed; restore its original path"
    );
    let cfg = inspect(&profile.home)?;
    ensure!(
        cfg.cluster.id == cluster && cfg.node.id == profile.node_id,
        "cluster profile identity changed; restore its original state"
    );
    Ok(cfg)
}

fn find(registry: &Contexts, name: &str) -> Result<String> {
    if registry.profiles.contains_key(name) {
        return Ok(name.into());
    }
    let matches: Vec<_> = registry
        .profiles
        .iter()
        .filter_map(|(id, profile)| {
            target(id, profile)
                .ok()
                .filter(|cfg| cfg.cluster.name == name)
                .map(|_| id.clone())
        })
        .collect();
    ensure!(
        matches.len() == 1,
        "unknown or ambiguous cluster; use an ID from gent clusters"
    );
    Ok(matches[0].clone())
}

pub fn resolve(root: &Path, selected: Option<&str>) -> Result<PathBuf> {
    gent_daemon::recovery::ensure_active(root)?;
    let root = managed_file::normalize(root)?;
    if Snapshot::read(&config::path(&root))?.text.is_none() {
        ensure!(
            selected.is_none(),
            "no cluster profiles; initialize this Gent directory first"
        );
        return Ok(root);
    }
    let cfg = inspect(&root)?;
    let registry = registry(&root, &cfg)?;
    let id = selected
        .map(|name| find(&registry, name))
        .transpose()?
        .unwrap_or(registry.active_cluster.clone());
    let profile = &registry.profiles[&id];
    target(&id, profile)?;
    Ok(profile.home.clone())
}

pub fn list(root: &Path) -> Result<Value> {
    gent_daemon::recovery::ensure_active(root)?;
    let root = managed_file::normalize(root)?;
    if Snapshot::read(&config::path(&root))?.text.is_none() {
        return Ok(json!({"active_cluster":null,"profiles":[]}));
    }
    let cfg = inspect(&root)?;
    let registry = registry(&root, &cfg)?;
    let profiles: Vec<_> = registry
        .profiles
        .iter()
        .map(|(id, profile)| {
            let mut value = json!({"cluster_id":id,"node_id":profile.node_id,"home":profile.home,
            "active":id==&registry.active_cluster});
            match target(id, profile) {
                Ok(cfg) => {
                    value["name"] = json!(cfg.cluster.name);
                    value["available"] = json!(true);
                }
                Err(error) => {
                    value["available"] = json!(false);
                    value["error"] = json!(error.to_string());
                }
            }
            value
        })
        .collect();
    Ok(
        json!({"active_cluster":registry.active_cluster,"profiles":profiles,
        "pending":provision::pending(&root,&cfg)?,"config":config::path(&root)}),
    )
}

pub fn add(root: &Path, directory: &Path) -> Result<Value> {
    gent_daemon::recovery::ensure_active(root)?;
    gent_daemon::recovery::ensure_active(directory)?;
    let root = managed_file::normalize(root)?;
    let directory = managed_file::normalize(directory)?;
    inspect(&root)?;
    let cfg = inspect(&directory)?;
    let profile = ContextProfile {
        home: directory.clone(),
        node_id: cfg.node.id.clone(),
    };
    config::edit_local(&root, |original| {
        let mut registry = registry(&root, original)?;
        if let Some(previous) = registry.profiles.get(&cfg.cluster.id) {
            ensure!(
                previous == &profile,
                "this cluster is already registered with another directory or node"
            );
        } else {
            ensure!(
                registry.profiles.len() < Contexts::LIMIT,
                "cluster profile limit reached"
            );
            registry
                .profiles
                .insert(cfg.cluster.id.clone(), profile.clone());
        }
        target(&cfg.cluster.id, &profile)?;
        original.set_contexts(registry)?;
        Ok(json!({"added":true,"cluster_id":cfg.cluster.id,"node_id":cfg.node.id,"home":directory}))
    })
}

fn choice(reader: &mut impl BufRead, writer: &mut impl Write, listing: &Value) -> Result<String> {
    let profiles = listing["profiles"]
        .as_array()
        .context("invalid profile list")?;
    let available: Vec<_> = profiles.iter().filter(|p| p["available"] == true).collect();
    ensure!(
        !available.is_empty(),
        "no available clusters; inspect gent clusters"
    );
    for (index, profile) in available.iter().enumerate() {
        writeln!(
            writer,
            "{}: {} ({})",
            index + 1,
            profile["name"].as_str().unwrap_or_default().escape_debug(),
            profile["cluster_id"].as_str().unwrap_or_default()
        )?;
    }
    write!(writer, "Select a cluster number: ")?;
    writer.flush()?;
    let mut input = String::new();
    let bytes = reader.take(4097).read_line(&mut input)?;
    ensure!(
        bytes > 0 && bytes <= 4096 && input.ends_with('\n'),
        "cluster selection cancelled or incomplete"
    );
    let index = input
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|n| n.checked_sub(1))
        .context("enter a listed cluster number")?;
    Ok(available
        .get(index)
        .context("enter a listed cluster number")?["cluster_id"]
        .as_str()
        .context("missing cluster ID")?
        .into())
}

pub fn switch(root: &Path, cluster: Option<String>, interactive: bool) -> Result<Value> {
    gent_daemon::recovery::ensure_active(root)?;
    let root = managed_file::normalize(root)?;
    let selected = match cluster {
        Some(cluster) => cluster,
        None => {
            ensure!(
                interactive && io::stdin().is_terminal() && io::stderr().is_terminal(),
                "pass a cluster ID or unique name: gent cluster switch CLUSTER"
            );
            choice(
                &mut io::stdin().lock(),
                &mut io::stderr().lock(),
                &list(&root)?,
            )?
        }
    };
    inspect(&root)?;
    config::edit_local(&root, |cfg| {
        let mut registry = registry(&root, cfg)?;
        let id = find(&registry, &selected)?;
        let profile = &registry.profiles[&id];
        let selected = target(&id, profile)?;
        let previous = registry.active_cluster.clone();
        let result = json!({"active_cluster":id,"previous_cluster":previous,"name":selected.cluster.name,
            "home":profile.home,"changed":previous!=id});
        registry.active_cluster = id;
        cfg.set_contexts(registry)?;
        Ok(result)
    })
}

pub fn print(value: &Value) {
    if let Some(profiles) = value["profiles"].as_array() {
        if profiles.is_empty() {
            println!("No local cluster profiles.");
        }
        for profile in profiles {
            println!(
                "{} {}  {}{}",
                if profile["active"] == true { "*" } else { " " },
                profile["cluster_id"].as_str().unwrap_or_default(),
                profile["name"]
                    .as_str()
                    .unwrap_or("unavailable")
                    .escape_debug(),
                if profile["available"] == true {
                    ""
                } else {
                    " (restore this profile's state)"
                }
            );
        }
        if let Some(pending) = value["pending"].as_array() {
            for job in pending {
                println!(
                    "Pending {}: {} ({}). Rerun the original setup command.",
                    job["intent"]["kind"].as_str().unwrap_or("setup"),
                    job["intent"]["name"]
                        .as_str()
                        .unwrap_or_default()
                        .escape_debug(),
                    job["home"].as_str().unwrap_or_default().escape_debug()
                );
            }
        }
    } else if value["added"] == true {
        println!(
            "Registered cluster {}. Select it with gent cluster switch {}.",
            value["cluster_id"].as_str().unwrap_or_default(),
            value["cluster_id"].as_str().unwrap_or_default()
        );
    } else {
        println!(
            "Active cluster: {} ({})",
            value["name"].as_str().unwrap_or_default().escape_debug(),
            value["active_cluster"].as_str().unwrap_or_default()
        );
    }
}

#[cfg(test)]
mod tests;
