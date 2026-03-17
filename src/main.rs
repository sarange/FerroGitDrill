use anyhow::{Result, anyhow};
use clap::Parser;
use colored::*;
use futures::stream::StreamExt;
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, USER_AGENT};
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, Semaphore, mpsc};

static RE_REFS: Lazy<Regex> = Lazy::new(|| Regex::new(r"(refs(/[a-zA-Z0-9\-\.\_\*]+)+)").unwrap());
static RE_SHA: Lazy<Regex> = Lazy::new(|| Regex::new(r"([a-f0-9]{40})").unwrap());
static RE_UNSAFE_CONFIG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^\s*(fsmonitor|sshcommand|askpass|editor|pager)").unwrap());

#[derive(Parser, Debug, Clone)]
#[command(
    name = "FerroGitDrill",
    author = "sarange",
    version,
    about = "A high-performance forensic tool for automated git repository discovery and reconstruction from exposed web endpoints.",
    long_about = "FerroGitDrill streamlines the process of recovering version control history from misconfigured web servers. It features heuristic object discovery, parallelized reconstruction, and automated workspace restoration."
)]
struct Args {
    #[arg(
        short,
        long,
        help = "Target remote endpoint URL (e.g., https://site.com/.git)"
    )]
    url: Option<String>,

    #[arg(
        short,
        long,
        help = "Path to a newline-delimited list of target URLs for batch processing"
    )]
    list: Option<String>,

    #[arg(
        short,
        long,
        help = "Destination path for reconstructed repositories (serves as parent directory in batch mode)"
    )]
    output: Option<String>,

    #[arg(
        short,
        long,
        help = "Network proxy configuration (supports HTTP, HTTPS, SOCKS4, SOCKS5)"
    )]
    proxy: Option<String>,

    #[arg(
        short,
        long,
        default_value_t = 5,
        help = "Degree of parallelism (maximum simultaneous network requests)"
    )]
    jobs: usize,

    #[arg(
        short,
        long,
        default_value_t = 15,
        help = "Maximum concurrent repository reconstructions in batch mode"
    )]
    concurrency: usize,

    #[arg(
        short,
        long,
        default_value_t = 10,
        help = "Maximum re-transmission attempts for transient network failures"
    )]
    retry: u32,

    #[arg(
        short,
        long,
        default_value_t = 10,
        help = "Maximum allowable duration for individual network operations"
    )]
    timeout: u64,

    #[arg(
        short = 'a',
        long,
        default_value = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Trailer/93.3.8652.5",
        help = "Custom HTTP User-Agent identification string"
    )]
    user_agent: String,

    #[arg(
        short = 'H',
        long,
        help = "Inject supplemental HTTP headers (format: 'Key=Value')"
    )]
    headers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum TaskType {
    Download,
    RecursiveDownload,
    FindRefs,
    FindObjects,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Task {
    task_type: TaskType,
    file_path: String,
}

struct App {
    client: reqwest::Client,
    seen_tasks: Arc<Mutex<HashSet<Task>>>,
    base_url: String,
    output_dir: String,
    target_name: String,
    semaphore: Arc<Semaphore>,
}

impl App {
    fn log_info(&self, msg: &str) {
        println!(
            "{} [{}] {}",
            "󰋼 INFO".blue().bold(),
            self.target_name.cyan(),
            msg
        );
    }

    fn log_success(&self, msg: &str) {
        println!(
            "{} [{}] {}",
            "󰄬 DONE".green().bold(),
            self.target_name.cyan(),
            msg
        );
    }

    fn log_warn(&self, msg: &str) {
        println!(
            "{} [{}] {}",
            "󰀦 WARN".yellow().bold(),
            self.target_name.cyan(),
            msg
        );
    }

    fn log_error(&self, msg: &str) {
        eprintln!(
            "{} [{}] {}",
            "󰅚 ERROR".red().bold(),
            self.target_name.cyan(),
            msg
        );
    }

    fn log_sync(&self, file: &str, status: &str) {
        let status_color = if status.contains("200") {
            status.green()
        } else {
            status.yellow()
        };
        println!(
            "{} [{}] Syncing {} [{}]",
            "󰇚".cyan(),
            self.target_name.dimmed(),
            file.dimmed(),
            status_color
        );
    }

    fn new(args: Args, url: String, output_dir: String) -> Result<Self> {
        let mut base_url = url.trim_end_matches('/').to_string();
        if base_url.ends_with("/HEAD") {
            base_url = base_url.trim_end_matches("/HEAD").to_string();
        } else if base_url.ends_with("HEAD") {
            base_url = base_url.trim_end_matches("HEAD").to_string();
        }

        if base_url.ends_with("/.git") {
            base_url = base_url.trim_end_matches("/.git").to_string();
        } else if base_url.ends_with(".git") {
            base_url = base_url.trim_end_matches(".git").to_string();
        }
        let base_url = base_url.trim_end_matches('/').to_string();

        let parsed_url = url::Url::parse(&url)?;
        let target_name = parsed_url.host_str().unwrap_or("unknown").to_string();

        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, HeaderValue::from_str(&args.user_agent)?);
        for h in &args.headers {
            if let Some((k, v)) = h.split_once('=') {
                headers.insert(
                    HeaderName::from_bytes(k.trim().as_bytes())?,
                    HeaderValue::from_str(v.trim())?,
                );
            }
        }

        let mut client_builder = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(args.timeout))
            .danger_accept_invalid_certs(true);

        if let Some(proxy_url) = &args.proxy {
            client_builder = client_builder.proxy(reqwest::Proxy::all(proxy_url)?);
        }

        let client = client_builder.build()?;
        let jobs = args.jobs;

        Ok(App {
            client,
            seen_tasks: Arc::new(Mutex::new(HashSet::new())),
            base_url,
            output_dir,
            target_name,
            semaphore: Arc::new(Semaphore::new(jobs)),
        })
    }

    async fn add_task(&self, tx: &mpsc::Sender<Task>, task: Task) {
        let mut seen = self.seen_tasks.lock().await;
        if seen.insert(task.clone()) {
            let _ = tx.send(task).await;
        }
    }

    async fn download_file(&self, file_path: &str) -> Result<()> {
        let url = format!("{}/{}", self.base_url, file_path.trim_start_matches('/'));
        let dest = PathBuf::from(&self.output_dir).join(file_path.trim_start_matches('/'));

        if dest.exists() && !file_path.ends_with('/') {
            return Ok(());
        }

        let _permit = self.semaphore.acquire().await?;
        let resp = self.client.get(&url).send().await?;
        let status = resp.status();

        if !status.is_success() {
            return Err(anyhow!("Status code {}", status));
        }

        let content_type = resp.headers().get(reqwest::header::CONTENT_TYPE);
        if let Some(ct) = content_type {
            if ct.to_str()?.contains("text/html") && !file_path.ends_with('/') {
                return Err(anyhow!("HTML ignored"));
            }
        }

        self.log_sync(file_path, &status.to_string());

        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).await?;
        }

        let mut file = fs::File::create(dest).await?;
        let content = resp.bytes().await?;
        file.write_all(&content).await?;

        Ok(())
    }

    async fn do_recursive_download(&self, tx: &mpsc::Sender<Task>, file_path: &str) -> Result<()> {
        let url = format!("{}/{}", self.base_url, file_path.trim_start_matches('/'));
        let _permit = self.semaphore.acquire().await?;
        let resp = self.client.get(&url).send().await?;
        let status = resp.status();
        self.log_sync(file_path, &status.to_string());

        if status.is_redirection() && !file_path.ends_with('/') {
            if let Some(loc) = resp.headers().get(reqwest::header::LOCATION) {
                if loc.to_str()?.ends_with(&(file_path.to_string() + "/")) {
                    self.add_task(
                        tx,
                        Task {
                            task_type: TaskType::RecursiveDownload,
                            file_path: file_path.to_string() + "/",
                        },
                    )
                    .await;
                    return Ok(());
                }
            }
        }

        if file_path.ends_with('/') {
            let body = resp.text().await?;
            let mut hrefs = Vec::new();
            {
                let document = Html::parse_document(&body);
                let selector = Selector::parse("a").unwrap();

                for element in document.select(&selector) {
                    if let Some(href) = element.value().attr("href") {
                        if is_safe_path(href) && !href.starts_with("http") {
                            hrefs.push(href.to_string());
                        }
                    }
                }
            }

            for href in hrefs {
                self.add_task(
                    tx,
                    Task {
                        task_type: TaskType::RecursiveDownload,
                        file_path: format!("{}{}", file_path, href),
                    },
                )
                .await;
            }
        } else if status.is_success() {
            let dest = PathBuf::from(&self.output_dir).join(file_path.trim_start_matches('/'));
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent).await?;
            }
            let mut file = fs::File::create(dest).await?;
            let content = resp.bytes().await?;
            file.write_all(&content).await?;
        }

        Ok(())
    }

    async fn do_find_refs(&self, tx: &mpsc::Sender<Task>, file_path: &str) -> Result<()> {
        let _ = self.download_file(file_path).await;
        let full_path = PathBuf::from(&self.output_dir).join(file_path.trim_start_matches('/'));
        if !full_path.exists() || full_path.is_dir() {
            return Ok(());
        }

        let content = fs::read(&full_path).await?;
        let content_str = String::from_utf8_lossy(&content);

        for cap in RE_REFS.captures_iter(&content_str) {
            let ref_path = &cap[1];
            if !ref_path.ends_with('*') && is_safe_path(ref_path) {
                self.add_task(
                    tx,
                    Task {
                        task_type: TaskType::Download,
                        file_path: format!(".git/{}", ref_path),
                    },
                )
                .await;
                self.add_task(
                    tx,
                    Task {
                        task_type: TaskType::Download,
                        file_path: format!(".git/logs/{}", ref_path),
                    },
                )
                .await;
            }
        }

        for cap in RE_SHA.captures_iter(&content_str) {
            self.add_task(
                tx,
                Task {
                    task_type: TaskType::FindObjects,
                    file_path: cap[1].to_string(),
                },
            )
            .await;
        }

        Ok(())
    }

    async fn do_find_objects(&self, tx: &mpsc::Sender<Task>, sha: &str) -> Result<()> {
        let file_path = format!(".git/objects/{}/{}", &sha[..2], &sha[2..]);
        let full_path = PathBuf::from(&self.output_dir).join(&file_path);

        if !full_path.exists() {
            let _ = self.download_file(&file_path).await;
        }

        if full_path.exists() && !full_path.is_dir() {
            let referenced = get_referenced_shas(&full_path, &self.output_dir);
            for r_sha in referenced {
                self.add_task(
                    tx,
                    Task {
                        task_type: TaskType::FindObjects,
                        file_path: r_sha,
                    },
                )
                .await;
            }
        }

        Ok(())
    }
}

fn is_safe_path(path: &str) -> bool {
    !path.is_empty() && !path.starts_with('/') && !path.contains("..")
}

fn get_referenced_shas(path: &Path, base_dir: &str) -> Vec<String> {
    let mut shas = Vec::new();
    let git_dir = Path::new(base_dir).join(".git");

    if let Ok(repo) = git2::Repository::open_bare(&git_dir) {
        let sha = path_to_sha(path);
        if let Ok(oid) = git2::Oid::from_str(&sha) {
            if let Ok(obj) = repo.find_object(oid, None) {
                match obj.kind() {
                    Some(git2::ObjectType::Commit) => {
                        if let Some(commit) = obj.as_commit() {
                            shas.push(commit.tree_id().to_string());
                            for parent in commit.parents() {
                                shas.push(parent.id().to_string());
                            }
                        }
                    }
                    Some(git2::ObjectType::Tree) => {
                        if let Some(tree) = obj.as_tree() {
                            for entry in tree.iter() {
                                shas.push(entry.id().to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    shas
}

fn path_to_sha(path: &Path) -> String {
    let components: Vec<_> = path.components().collect();
    if components.len() >= 2 {
        let second = components[components.len() - 1]
            .as_os_str()
            .to_str()
            .unwrap_or("");
        let first = components[components.len() - 2]
            .as_os_str()
            .to_str()
            .unwrap_or("");
        format!("{}{}", first, second)
    } else {
        "".to_string()
    }
}

async fn sanitize_config(app: &App) -> Result<()> {
    let path = PathBuf::from(&app.output_dir).join(".git/config");
    if !path.exists() || path.is_dir() {
        return Ok(());
    }
    let content = fs::read_to_string(&path).await?;
    let mut new_content = String::with_capacity(content.len());

    for line in content.lines() {
        if RE_UNSAFE_CONFIG.is_match(line) {
            app.log_warn(&format!(
                "Neutralized unsafe config option: '{}'",
                line.trim()
            ));
            new_content.push_str("# ");
        }
        new_content.push_str(line);
        new_content.push('\n');
    }
    fs::write(path, new_content).await?;
    Ok(())
}

async fn run_recovery(app: Arc<App>) -> Result<()> {
    if !Path::new(&app.output_dir).exists() {
        fs::create_dir_all(&app.output_dir).await?;
    }

    let (tx, mut rx) = mpsc::channel::<Task>(100000);

    app.log_info(&format!(
        "Analyzing remote target: {}",
        app.base_url.bold().cyan()
    ));

    let head_url = format!("{}/.git/HEAD", app.base_url);
    let resp = app.client.get(&head_url).send().await?;
    if !resp.status().is_success() {
        app.log_error(&format!(
            "Endpoint unreachable: .git/HEAD status {}",
            resp.status()
        ));
        return Err(anyhow!("HEAD inaccessible"));
    }

    let git_url = format!("{}/.git/", app.base_url);
    let resp = app.client.get(&git_url).send().await?;
    let mut is_listing = false;
    if resp.status().is_success() {
        let body = resp.text().await?;
        if body.contains("HEAD") {
            is_listing = true;
        }
    }

    if is_listing {
        app.log_info("Discovery: Directory listing enabled. Reconstruction started.");
        app.add_task(
            &tx,
            Task {
                task_type: TaskType::RecursiveDownload,
                file_path: ".git/".to_string(),
            },
        )
        .await;
        app.add_task(
            &tx,
            Task {
                task_type: TaskType::RecursiveDownload,
                file_path: ".gitignore".to_string(),
            },
        )
        .await;
    } else {
        app.log_info("Discovery: Directory listing denied. Using heuristic mapping.");
        let common = vec![
            ".gitignore",
            ".git/COMMIT_EDITMSG",
            ".git/description",
            ".git/index",
            ".git/config",
            ".git/info/exclude",
            ".git/objects/info/packs",
        ];
        for f in common {
            app.add_task(
                &tx,
                Task {
                    task_type: TaskType::Download,
                    file_path: f.to_string(),
                },
            )
            .await;
        }

        let refs = vec![
            ".git/FETCH_HEAD",
            ".git/HEAD",
            ".git/ORIG_HEAD",
            ".git/info/refs",
            ".git/logs/HEAD",
            ".git/logs/refs/heads/main",
            ".git/logs/refs/heads/master",
            ".git/logs/refs/remotes/origin/HEAD",
            ".git/packed-refs",
            ".git/refs/heads/main",
            ".git/refs/heads/master",
            ".git/refs/remotes/origin/HEAD",
        ];
        for f in refs {
            app.add_task(
                &tx,
                Task {
                    task_type: TaskType::FindRefs,
                    file_path: f.to_string(),
                },
            )
            .await;
        }
    }

    let mut workers = futures::stream::FuturesUnordered::new();

    loop {
        tokio::select! {
            task_opt = rx.recv() => {
                match task_opt {
                    Some(task) => {
                        let app_c = app.clone();
                        let tx_c = tx.clone();
                        workers.push(tokio::spawn(async move {
                            match task.task_type {
                                TaskType::Download => app_c.download_file(&task.file_path).await,
                                TaskType::RecursiveDownload => app_c.do_recursive_download(&tx_c, &task.file_path).await,
                                TaskType::FindRefs => app_c.do_find_refs(&tx_c, &task.file_path).await,
                                TaskType::FindObjects => app_c.do_find_objects(&tx_c, &task.file_path).await,
                            }
                        }));
                    }
                    None => if workers.is_empty() { break },
                }
            }
            Some(res) = workers.next() => {
                if let Err(e) = res {
                    app.log_error(&format!("Worker execution failure: {}", e));
                }
            }
        }

        if workers.is_empty() && rx.is_empty() {
            break;
        }
    }

    app.log_info("Mapping: Resolving objects from index entries.");
    let index_path = PathBuf::from(&app.output_dir).join(".git/index");
    if index_path.exists() {
        if let Ok(index) = git2::Index::open(&index_path) {
            for entry in index.iter() {
                app.add_task(
                    &tx,
                    Task {
                        task_type: TaskType::FindObjects,
                        file_path: entry.id.to_string(),
                    },
                )
                .await;
            }
        }
    }

    while let Ok(task) = rx.try_recv() {
        let app_c = app.clone();
        let tx_c = tx.clone();
        workers.push(tokio::spawn(async move {
            match task.task_type {
                TaskType::Download => app_c.download_file(&task.file_path).await,
                TaskType::RecursiveDownload => {
                    app_c.do_recursive_download(&tx_c, &task.file_path).await
                }
                TaskType::FindRefs => app_c.do_find_refs(&tx_c, &task.file_path).await,
                TaskType::FindObjects => app_c.do_find_objects(&tx_c, &task.file_path).await,
            }
        }));
    }

    while let Some(res) = workers.next().await {
        if let Err(e) = res {
            app.log_error(&format!("Final worker failure: {}", e));
        }
    }

    app.log_info("System: Neutralizing environment configuration.");
    sanitize_config(&app).await?;

    app.log_info("Restoration: Building working tree.");
    let _ = tokio::process::Command::new("git")
        .arg("checkout")
        .arg(".")
        .current_dir(&app.output_dir)
        .status()
        .await;

    app.log_success(&format!(
        "Repository reconstruction successful: {}",
        app.output_dir.bold().green()
    ));
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(list_file) = &args.list {
        let parent_dir = args
            .output
            .clone()
            .ok_or_else(|| anyhow!("Batch mode requires a parent --output directory"))?;
        let content = fs::read_to_string(list_file).await?;
        let urls: Vec<String> = content
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        fs::create_dir_all(&parent_dir).await?;

        let mut recovery_tasks = futures::stream::iter(urls)
            .map(|url| {
                let args_c = args.clone();
                let parent_dir_c = parent_dir.clone();
                async move {
                    let parsed_url = match url::Url::parse(&url) {
                        Ok(u) => u,
                        Err(e) => return Err(anyhow!("Invalid URL {}: {}", url, e)),
                    };
                    let host = parsed_url.host_str().unwrap_or("unknown").replace(".", "_");
                    let output_dir = PathBuf::from(&parent_dir_c)
                        .join(host)
                        .to_string_lossy()
                        .to_string();

                    let app = Arc::new(App::new(args_c, url, output_dir)?);
                    run_recovery(app).await
                }
            })
            .buffer_unordered(args.concurrency);

        while let Some(res) = recovery_tasks.next().await {
            if let Err(e) = res {
                eprintln!("{} Batch task failed: {}", "󰅚 ERROR".red().bold(), e);
            }
        }
    } else {
        let url = args
            .url
            .clone()
            .ok_or_else(|| anyhow!("Target --url or --list is mandatory"))?;
        let output_dir = if let Some(out) = args.output.clone() {
            out
        } else {
            let parsed_url = url::Url::parse(&url)?;
            parsed_url
                .host_str()
                .unwrap_or("reconstructed_repo")
                .replace(".", "_")
        };
        let app = Arc::new(App::new(args, url, output_dir)?);
        run_recovery(app).await?;
    }

    Ok(())
}
