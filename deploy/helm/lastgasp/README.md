# lastgasp Helm chart

Runs the lastgasp agent on every node (DaemonSet) and the lastgasp server with its web UI (Deployment).

```sh
helm install lastgasp oci://git.fferrando.cc/rdfilippo/lastgasp -n lastgasp --create-namespace
```

All values are described in `values.yaml`. The full guide is in [docs/kubernetes.md](../../../docs/kubernetes.md).
