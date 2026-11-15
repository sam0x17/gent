//! Persist only validated native listener arguments, never credential contents.
use super::*;
use anyhow::Context;

impl Run {
    pub(crate) async fn for_service(&self, home: &Path) -> Result<Self> {
        let mut options = self.clone();
        for path in [&mut options.tls_cert, &mut options.tls_key]
            .into_iter()
            .flatten()
        {
            *path = managed_file::normalize(path)?;
        }
        options.service_arguments()?;
        server::validate(home, &options).await?;
        Ok(options)
    }

    pub(crate) fn service_arguments(&self) -> Result<Vec<String>> {
        ensure!(
            self.listen.port() != 0,
            "gateway service needs a fixed nonzero port"
        );
        let mut args = vec![
            "gateway".into(),
            "run".into(),
            "--listen".into(),
            self.listen.to_string(),
        ];
        for (flag, path) in [("--tls-cert", &self.tls_cert), ("--tls-key", &self.tls_key)] {
            if let Some(path) = path {
                ensure!(
                    path.is_absolute(),
                    "gateway service TLS paths must be absolute"
                );
                args.extend([
                    flag.into(),
                    path.to_str().context("TLS path must be UTF-8")?.into(),
                ]);
            }
        }
        if let Some(origin) = &self.origin {
            args.extend(["--origin".into(), origin.clone()]);
        }
        for (flag, values) in [
            ("--client-metadata", &self.client_metadata),
            ("--file-origin", &self.file_origin),
            ("--file-downloads", &self.file_downloads),
        ] {
            ensure!(values.len() <= 128, "too many gateway service arguments");
            for value in values {
                args.extend([flag.into(), value.clone()]);
            }
        }
        ensure!(
            args.iter()
                .all(|arg| arg.len() <= 4096 && !arg.chars().any(char::is_control))
                && args.iter().map(String::len).sum::<usize>() <= 32 * 1024,
            "gateway service arguments exceed limits or contain controls"
        );
        Ok(args)
    }
}
