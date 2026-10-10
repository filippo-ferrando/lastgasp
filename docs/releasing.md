# Releasing

CI runs on the Forgejo instance with Forgejo Actions. The workflows are in `.forgejo/workflows/`.

| Workflow | Runs on | Does |
| --- | --- | --- |
| `ci.yaml` | pushes to `main` and pull requests | gofmt check, `go vet`, a build for each release architecture, `make test` |
| `release.yaml` | a pushed tag like `v1.2.0` (`v*.*.*`) | the same tests, then the release files, the server and agent images and the Helm chart |

## Cut a release

1. When the release needs an action on upgrade, write it in [upgrade-notes.md](upgrade-notes.md) under `## Unreleased`, and rename that heading to the tag, with a new `## Unreleased` section above it (`make test` needs one). The release notes start with the section of the tag.
2. Tag and push:

```sh
git tag -a v1.2.0 -m "v1.2.0"
git push origin v1.2.0
```

A tag with a dash, like `v1.2.0-rc1`, makes a prerelease and does not move the `latest`, `1.2` and `1.2.0` image tags.

`release.yaml` has five jobs:

| Job | Does |
| --- | --- |
| `test` | `go vet` and `make test` |
| `build` | `make dist VERSION=v1.2.0`, writes the release notes (upgrade notes of the tag, install line, image name, changes since the previous tag), keeps both as an artifact |
| `image` | installs the Docker CLI, sets up buildx, logs in to the registry, builds and pushes the server and agent images |
| `chart` | packages `deploy/helm/lastgasp` with the version of the tag and pushes it to the registry as an OCI chart |
| `release` | publishes the Forgejo release of the tag with `softprops/action-gh-release`, once `build`, `image` and `chart` worked |

The release holds:

| File | Content |
| --- | --- |
| `lastgasp-agent-linux-amd64`, `-arm64`, `-arm` | static agent binaries (arm is ARMv7) |
| `lastgasp-server-linux-amd64`, `-arm64`, `-arm` | static server binaries |
| `install-agent.sh` | the installer, with `VERSION=v1.2.0` set, so it installs this release |
| `lastgasp-agent.service`, `lastgasp-server.service` | systemd units |
| `SHA256SUMS` | checksums of all of the above, checked by the installer |

The image job builds the `server` and `agent` targets of `Dockerfile` for linux/amd64 and linux/arm64 with `docker/build-push-action` and pushes them to `git.internal.fferrando.cc/rdfilippo/lastgasp-server` and `.../lastgasp-agent` with the tags `v1.2.0`, `1.2.0`, `1.2` and `latest`. The chart job pushes `oci://git.internal.fferrando.cc/rdfilippo/lastgasp` with version `1.2.0` and app version `v1.2.0`, so its default images are the ones of the same release. The registry name is the `REGISTRY` variable at the top of the workflow. The build stage cross compiles, so no emulation is needed.

## Setup

| Item | Value |
| --- | --- |
| runner label | `ubuntu-latest`, with access to a Docker daemon for the image job, `python3` and `curl` for the script tests. `azure/setup-helm` installs helm for the chart tests |
| secret `LOCAL_TOKEN` | an access token of the user that pushes the tag (`github.actor`), with the `write:package` scope |
| release token | the automatic `GITHUB_TOKEN` of the runner, with `contents: write` |
| repository visibility | public, so agents download releases without a login |

Add secrets under the repository settings, Actions, Secrets.

## Build a release locally

```sh
make dist VERSION=v1.2.0      # dist/ with the same files, without uploading
make image VERSION=v1.2.0     # lastgasp-server:v1.2.0 for this machine only
make image-agent VERSION=v1.2.0   # lastgasp-agent:v1.2.0
```

`make dist` refuses a version that does not start with `v` and a digit, so a development build never gets a release installer. Builds without `VERSION` take the tag of the current commit, or show `dev` plus the commit.
