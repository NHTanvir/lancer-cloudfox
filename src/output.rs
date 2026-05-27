use anyhow::Result;
use comfy_table::{Table, ContentArrangement};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

pub struct OutputWriter {
    base: PathBuf,
}

impl OutputWriter {
    pub fn new(profile: &str, account_id: &str) -> Self {
        let home = dirs_next();
        let base = home
            .join(".cloudfox")
            .join("cloudfox-output")
            .join("aws")
            .join(format!("{}-{}", profile, account_id));
        Self { base }
    }

    pub fn new_for(cloud: &str, key: &str) -> Self {
        let home = dirs_next();
        let base = home
            .join(".cloudfox")
            .join("cloudfox-output")
            .join(cloud)
            .join(key);
        Self { base }
    }

    pub fn table_path(&self, name: &str) -> PathBuf {
        self.base.join("table").join(format!("{}.txt", name))
    }

    pub fn csv_path(&self, name: &str) -> PathBuf {
        self.base.join("table").join(format!("{}.csv", name))
    }

    pub fn json_path(&self, name: &str) -> PathBuf {
        self.base.join("table").join(format!("{}.json", name))
    }

    pub fn loot_path(&self, dir: &str, name: &str) -> PathBuf {
        self.base.join("loot").join(dir).join(name)
    }

    pub fn print_table(&self, headers: &[&str], rows: &[Vec<String>]) {
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(headers.iter().map(|h| h.to_string()).collect::<Vec<_>>());
        for row in rows {
            table.add_row(row.iter().map(|c| c.as_str()).collect::<Vec<_>>());
        }
        println!("{table}");
    }

    pub fn write_table(&self, name: &str, headers: &[&str], rows: &[Vec<String>]) -> Result<()> {
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header(headers.iter().map(|h| h.to_string()).collect::<Vec<_>>());
        for row in rows {
            table.add_row(row.iter().map(|c| c.as_str()).collect::<Vec<_>>());
        }
        let path = self.table_path(name);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(&path, table.to_string())?;
        Ok(())
    }

    pub fn write_csv<T: Serialize>(&self, name: &str, rows: &[T]) -> Result<()> {
        let path = self.csv_path(name);
        fs::create_dir_all(path.parent().unwrap())?;
        let mut wtr = csv::Writer::from_path(&path)?;
        for row in rows {
            wtr.serialize(row)?;
        }
        wtr.flush()?;
        Ok(())
    }

    pub fn write_json<T: Serialize>(&self, name: &str, data: &T) -> Result<()> {
        let path = self.json_path(name);
        fs::create_dir_all(path.parent().unwrap())?;
        let f = fs::File::create(&path)?;
        serde_json::to_writer_pretty(f, data)?;
        Ok(())
    }

    pub fn loot_file(&self, dir: &str, name: &str, body: impl AsRef<[u8]>) -> Result<()> {
        let path = self.loot_path(dir, name);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(&path, body)?;
        Ok(())
    }

    pub fn loot_commands(&self, name: &str, body: &str) -> Result<()> {
        let path = self.base.join("loot").join(format!("{}.txt", name));
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(&path, body)?;
        eprintln!("[+] Loot commands written to {}", path.display());
        Ok(())
    }

    pub fn base_dir(&self) -> &Path {
        &self.base
    }
}

fn dirs_next() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOMEDRIVE").and_then(|d| std::env::var("HOMEPATH").map(|p| d + &p)))
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("C:\\Users\\Default"))
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("/tmp"))
    }
}
