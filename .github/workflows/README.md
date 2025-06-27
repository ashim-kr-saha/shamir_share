# GitHub Actions Workflows

This directory contains the CI/CD workflows for the `shamir_share` project.

## 📋 Workflow Overview

### 🔍 `pr_benchmark_check.yml`
**Purpose**: Prevents performance regressions in pull requests
- **Triggers**: On pull requests to `main` branch
- **Action**: Compares PR performance against base branch
- **Result**: Fails build if significant regression detected

### 📈 `main_benchmark_history.yml`
**Purpose**: Tracks long-term performance history
- **Triggers**: On pushes to `main` branch  
- **Action**: Updates performance history and generates reports
- **Result**: Creates visual performance charts on GitHub Pages

### 🚀 `publish.yml`
**Purpose**: Publishes releases to crates.io
- **Triggers**: On version tags
- **Action**: Builds and publishes the crate

## 🎯 Quick Start

1. **Enable GitHub Pages**: Go to repository Settings → Pages → Select `gh-pages` branch
2. **Merge a PR**: The regression check will run automatically
3. **Push to main**: History tracking will start building performance data
4. **View reports**: Visit `https://<username>.github.io/<repo-name>/`

## 📚 Documentation

For detailed setup and usage instructions, see:
- [CI Benchmark Setup Guide](../../.docs/CI_BENCHMARK_SETUP.md)

## 🛠️ Troubleshooting

- **Workflow failures**: Check the Actions tab for detailed logs
- **Permission issues**: Ensure repository has Actions enabled
- **Performance reports**: May take 1-2 pushes to `main` to appear

## 🔧 Customization

To modify benchmark behavior:
- Edit environment variables in the workflow files
- Adjust timeout values for longer/shorter runs
- Modify benchmark selection in the `cargo bench` commands