"""Executes Prowler against an AWS account and returns the output path."""

import subprocess
import shutil
from pathlib import Path


def run_prowler_docker(config: dict) -> Path:
    """
    Runs Prowler via Docker using credentials from the environment or AWS profile.

    Requires Docker to be installed and the calling process to have valid AWS credentials
    (environment variables or ~/.aws/credentials).

    Returns the path to the output JSON file.
    """
    aws_cfg = config.get("aws", {})
    prowler_cfg = config.get("prowler", {})
    output_dir = Path(config.get("outputs", {}).get("local_path", "outputs/prowler")).parent / "prowler"
    output_dir.mkdir(parents=True, exist_ok=True)

    image = prowler_cfg.get("docker_image", "public.ecr.aws/prowler-cloud/prowler:latest")
    region = aws_cfg.get("region", "us-east-1")
    severity_filter = prowler_cfg.get("severity_filter", ["critical", "high"])
    services = prowler_cfg.get("services", [])
    extra_flags = prowler_cfg.get("extra_flags", "")
    output_filename = prowler_cfg.get("output_filename", "prowler_output.json")

    output_path = output_dir / output_filename

    cmd = [
        "docker", "run", "--rm",
        "-e", "AWS_ACCESS_KEY_ID",
        "-e", "AWS_SECRET_ACCESS_KEY",
        "-e", "AWS_SESSION_TOKEN",
        "-e", "AWS_DEFAULT_REGION=" + region,
        "-v", f"{output_dir.resolve()}:/tmp/prowler-output",
        image,
        "aws",
        "--output-formats", "json",
        "--output-directory", "/tmp/prowler-output",
        "--output-filename", output_filename.replace(".json", ""),
    ]

    if severity_filter:
        cmd += ["--severity"] + severity_filter

    if services:
        cmd += ["--services"] + services

    if extra_flags:
        cmd += extra_flags.split()

    print(f"[runner] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False)

    if result.returncode not in (0, 3):
        # Prowler exits 3 when findings exist but scan completed — treat as success
        raise RuntimeError(f"Prowler exited with code {result.returncode}")

    if not output_path.exists():
        raise FileNotFoundError(f"Expected Prowler output not found: {output_path}")

    return output_path


def run_prowler_native(config: dict) -> Path:
    """
    Runs Prowler natively (must be installed and on PATH).
    Alternative to Docker for environments where Docker is unavailable.
    """
    if not shutil.which("prowler"):
        raise RuntimeError("prowler not found on PATH — install it or use Docker mode")

    aws_cfg = config.get("aws", {})
    prowler_cfg = config.get("prowler", {})
    output_dir = Path(prowler_cfg.get("output_dir", "outputs/prowler"))
    output_dir.mkdir(parents=True, exist_ok=True)

    region = aws_cfg.get("region", "us-east-1")
    severity_filter = prowler_cfg.get("severity_filter", ["critical", "high"])
    services = prowler_cfg.get("services", [])
    output_filename = prowler_cfg.get("output_filename", "prowler_output.json")

    output_path = output_dir / output_filename

    cmd = [
        "prowler", "aws",
        "--output-formats", "json",
        "--output-directory", str(output_dir),
        "--output-filename", output_filename.replace(".json", ""),
        "--region", region,
    ]

    if severity_filter:
        cmd += ["--severity"] + severity_filter

    if services:
        cmd += ["--services"] + services

    print(f"[runner] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=False)

    if result.returncode not in (0, 3):
        raise RuntimeError(f"Prowler exited with code {result.returncode}")

    if not output_path.exists():
        raise FileNotFoundError(f"Expected Prowler output not found: {output_path}")

    return output_path
