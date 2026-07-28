#!/usr/bin/env python3
"""Deterministic target generator for security scanning pipelines.

Generates ~7000 platform-specific target URIs and idempotently appends them to
``$HOME/paste_box.txt`` inside a begin/end marker block.  Repeated runs replace
the existing block rather than duplicating targets.

No real secrets or fake credentials are emitted.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Target counts per platform.  The total is intentionally ~7000.
TARGET_COUNTS = {
    "github": 1800,
    "gitlab": 800,
    "huggingface": 600,
    "docker": 700,
    "circleci": 400,
    "postman": 400,
    "aws_s3": 700,
    "gcs": 700,
    "jenkins": 400,
    "elasticsearch": 300,
    "syslog": 200,
}

PASTE_BOX = Path.home() / "paste_box.txt"
BEGIN_MARKER = "# === BEGIN GENERATED TARGETS ==="
END_MARKER = "# === END GENERATED TARGETS ==="


def _take(items: list[str], n: int) -> list[str]:
    """Return up to ``n`` items from ``items``."""
    return items[:n]


def _cartesian(prefix: str, parts: list[list[str]], n: int) -> list[str]:
    """Build ``prefix://a/b/...`` strings from nested part lists, capped at ``n``."""
    out: list[str] = []
    for combo in _nested(parts):
        out.append(f"{prefix}://" + "/".join(combo))
        if len(out) >= n:
            break
    return out


def _nested(parts: list[list[str]]) -> list[list[str]]:
    """Deterministic nested product of string lists."""
    if not parts:
        return [[]]
    result: list[list[str]] = [[]]
    for part in parts:
        new_result: list[list[str]] = []
        for combo in result:
            for value in part:
                new_result.append(combo + [value])
        result = new_result
    return result


# ---------------------------------------------------------------------------
# Platform-specific generators
# ---------------------------------------------------------------------------

def generate_github_targets(n: int) -> list[str]:
    """Curated public GitHub owners and repository names."""
    owners = [
        "google", "microsoft", "facebook", "apple", "amazon", "netflix", "apache",
        "mozilla", "kubernetes", "golang", "python", "rust-lang", "torvalds",
        "vercel", "tailwindlabs", "facebookresearch", "openai", "huggingface",
        "stability-ai", "eleutherai", "pytorch", "tensorflow", "nodejs", "npm",
        "yarnpkg", "vuejs", "angular", "denoland", "ruby", "rails", "django",
        "spring-projects", "JetBrains", "Shopify", "Stripe", "Twilio", "MongoDB",
        "elastic", "hashicorp", "prometheus", "grafana", "istio", "docker",
        "kubernetes-sigs", "gitlabhq",
    ]
    repos = [
        "awesome", "react", "vue", "angular", "tensorflow", "pytorch", "kubernetes",
        "docker", "django", "flask", "spring-boot", "linux", "rust", "go", "node",
        "npm", "yarn", "vscode", "electron", "three.js", "next.js", "nuxt", "svelte",
        "laravel", "rails", "bootstrap", "material-ui", "ant-design", "express",
        "koa", "fastapi", "pandas", "numpy", "scikit-learn", "transformers",
        "stable-diffusion", "whisper", "llama", "langchain", "crewai", "cli", "docs",
        "website", "examples", "community", "dotfiles", "configs", "infra",
        "deployment", "ops", "devops",
    ]
    return _cartesian("github", [owners, repos], n)


def generate_gitlab_targets(n: int) -> list[str]:
    """Curated public GitLab groups and project names."""
    groups = [
        "gitlab-org", "fdroid", "gnome", "kde", "alpine", "archlinux", "debian",
        "python-gitlab", "inkscape", "blender", "nextcloud", "mozilla", "ollama",
        "gitlabhq", "exoplatform", "xwiki", "wireshark", "gnu", "eclipse", "sourceware",
    ]
    projects = [
        "website", "backend", "frontend", "api", "mobile", "docs", "core", "app",
        "cli", "sdk", "lib", "plugin", "theme", "extensions", "tests", "examples",
        "dashboard", "proxy", "worker", "gateway", "service", "bot", "parser",
        "compiler", "interpreter", "runtime", "framework", "utils", "helpers",
        "toolkit", "modules", "components", "templates", "configs", "scripts",
        "deployment", "ci-cd", "security", "monitoring", "logging", "analytics",
    ]
    return _cartesian("gitlab", [groups, projects], n)


def generate_huggingface_targets(n: int) -> list[str]:
    """Curated public Hugging Face organisations and model/dataset names."""
    orgs = [
        "google", "microsoft", "facebook", "openai", "stabilityai", "meta-llama",
        "eleutherai", "bigscience", "HuggingFaceH4", "tiiuae", "mosaicml", "anthropic",
        "nvidia", "allenai", "sentence-transformers", "ollama", "runwayml",
        "StabilityAI", "comfyanonymous", "openbmb",
    ]
    resources = [
        "bert-base-uncased", "roberta-base", "gpt2", "t5-base", "t5-large",
        "whisper-base", "whisper-large", "llama-2-7b", "llama-2-13b",
        "stable-diffusion-xl", "stable-diffusion-2", "gpt-neo", "gpt-j",
        "falcon-7b", "falcon-40b", "mistral-7b", "mixtral-8x7b", "phi-2",
        "gemma-2b", "gemma-7b", "bnb-config", "safetensors", "tokenizer",
        "dataset", "model", "lora", "adapter", "onnx", "quantized", "embeddings",
    ]
    return _cartesian("huggingface", [orgs, resources], n)


def generate_docker_targets(n: int) -> list[str]:
    """Curated Docker Hub official-style images and tags."""
    images = [
        "ubuntu", "alpine", "node", "python", "nginx", "redis", "postgres", "mysql",
        "mongo", "httpd", "golang", "ruby", "php", "busybox", "debian", "centos",
        "fedora", "amazonlinux", "hello-world", "memcached", "elasticsearch",
        "logstash", "kibana", "jenkins", "gitlab-ce", "nextcloud", "wordpress",
        "drupal", "joomla", "ghost", "mariadb", "rabbitmq", "kafka", "zookeeper",
        "cassandra", "couchbase", "neo4j", "influxdb", "prometheus", "grafana",
        "traefik", "vault", "consul", "terraform", "ansible", "tomcat", "jetty",
        "maven", "gradle", "jruby", "openjdk", "eclipse-temurin", "rust", "swift",
        "dotnet", "perl", "r-base", "rails", "django", "flask", "fastapi",
        "express", "laravel", "spring-boot", "keycloak", "minio", "nats",
        "mosquitto", "redis-stack", "sonarqube", "nexus3", "registry", "haproxy",
        "varnish", "squid", "chronograf", "kapacitor", "telegraf",
    ]
    tags = ["latest", "slim", "alpine", "bullseye", "bookworm", "1", "2", "3", "4", "5"]
    out: list[str] = []
    for image in images:
        for tag in tags:
            out.append(f"docker://{image}:{tag}")
            if len(out) >= n:
                return out
    return out


def generate_circleci_targets(n: int) -> list[str]:
    """Curated CircleCI VCS provider / org / repo combinations."""
    vcs = ["github", "bitbucket"]
    orgs = [
        "trufflesecurity", "solana-labs", "ethereum", "bitcoin", "openzeppelin",
        "chainlink", "aave", "uniswap", "compound-finance", "makerdao",
        "graphprotocol", "ipfs", "filecoin", "polkadot", "cosmos", "tendermint",
        "hyperledger", "openssl", "mozilla", "apache",
    ]
    repos = ["project", "monorepo", "sdk", "contracts", "frontend", "backend",
             "docs", "tests", "app", "lib"]
    return _cartesian("circleci", [vcs, orgs, repos], n)


def generate_postman_targets(n: int) -> list[str]:
    """Representative public Postman workspace/collection slugs."""
    bases = [
        "postman-echo", "github-api", "twitter-api", "stripe-api", "weather-api",
        "ecommerce-api", "petstore", "google-maps", "twilio-api", "sendgrid-api",
    ]
    out: list[str] = []
    iteration = 1
    while len(out) < n:
        kind = "workspace" if iteration % 2 == 1 else "collection"
        for base in bases:
            out.append(f"postman://{kind}/{base}-{iteration:04d}")
            if len(out) >= n:
                break
        iteration += 1
    return out


def generate_aws_s3_targets(n: int) -> list[str]:
    """Placeholder public S3 bucket patterns (no real credentials)."""
    return [f"s3://public-dataset-placeholder-{i:04d}" for i in range(1, n + 1)]


def generate_gcs_targets(n: int) -> list[str]:
    """Placeholder public GCS bucket patterns (no real credentials)."""
    return [f"gs://public-bucket-placeholder-{i:04d}" for i in range(1, n + 1)]


def generate_jenkins_targets(n: int) -> list[str]:
    """Placeholder Jenkins deployment patterns (private by default)."""
    jobs = ["app", "frontend", "backend", "api"]
    out: list[str] = []
    host_num = 1
    while len(out) < n:
        host = f"jenkins-{host_num:03d}.example.com"
        for job in jobs:
            out.append(f"jenkins://{host}/job/{job}")
            if len(out) >= n:
                break
        host_num += 1
    return out


def generate_elasticsearch_targets(n: int) -> list[str]:
    """Placeholder Elasticsearch deployment patterns (private by default)."""
    indices = ["logs", "metrics", "events"]
    out: list[str] = []
    host_num = 1
    while len(out) < n:
        host = f"es-{host_num:03d}.example.com"
        for index in indices:
            out.append(f"elasticsearch://{host}:9200/{index}")
            if len(out) >= n:
                break
        host_num += 1
    return out


def generate_syslog_targets(n: int) -> list[str]:
    """Placeholder Syslog endpoint patterns (private by default)."""
    return [f"syslog://logs-{i:03d}.example.com:514" for i in range(1, n + 1)]


# ---------------------------------------------------------------------------
# Paste-box update
# ---------------------------------------------------------------------------

def update_paste_box(targets_by_platform: dict[str, list[str]], path: Path) -> None:
    """Idempotently replace the generated target block inside ``path``."""
    lines: list[str] = []
    if path.exists():
        with path.open("r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()

    begin_idx: int | None = None
    end_idx: int | None = None
    for i, line in enumerate(lines):
        if line.strip() == BEGIN_MARKER:
            begin_idx = i
        elif line.strip() == END_MARKER and begin_idx is not None:
            end_idx = i
            break

    block_lines = [BEGIN_MARKER, "# Generated by target_generator.py - do not edit manually between markers"]
    for platform, targets in targets_by_platform.items():
        block_lines.append(f"# --- {platform}: {len(targets)} targets ---")
        block_lines.extend(targets)
    block_lines.append(END_MARKER)

    if begin_idx is not None and end_idx is not None:
        new_lines = lines[: begin_idx + 1] + block_lines[1:-1] + lines[end_idx:]
    else:
        new_lines = lines[:]
        if new_lines and new_lines[-1] != "":
            new_lines.append("")
        new_lines.extend(block_lines)

    path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    """Generate deterministic targets and update ``paste_box.txt``."""
    generators = [
        ("github", generate_github_targets),
        ("gitlab", generate_gitlab_targets),
        ("huggingface", generate_huggingface_targets),
        ("docker", generate_docker_targets),
        ("circleci", generate_circleci_targets),
        ("postman", generate_postman_targets),
        ("aws_s3", generate_aws_s3_targets),
        ("gcs", generate_gcs_targets),
        ("jenkins", generate_jenkins_targets),
        ("elasticsearch", generate_elasticsearch_targets),
        ("syslog", generate_syslog_targets),
    ]

    targets_by_platform: dict[str, list[str]] = {}
    for platform, gen in generators:
        targets_by_platform[platform] = gen(TARGET_COUNTS[platform])

    update_paste_box(targets_by_platform, PASTE_BOX)

    total = 0
    print("Generated target counts:")
    for platform, targets in targets_by_platform.items():
        count = len(targets)
        total += count
        print(f"  {platform}: {count}")
    print(f"  total: {total}")
    print(f"Updated: {PASTE_BOX}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
