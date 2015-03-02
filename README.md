# etcd-manager

## Usage

The etcd-manager uses ssh to run remote commands on target etcd hosts. SSH auth requires an ssh-agent to be running.
Run the following command to ensure your SSH key is loaded:

```
ssh-add /path/to/ssh-private-key
``` 

### Get the etcd binary version

The following command will run `/opt/etcd/bin/etcd -version` on each host.

```
etcd-manager version -hosts '130.211.162.53:22,107.178.221.96:22,104.154.62.70:22'
```

### Deploying etcd

#### Deploy from a git tag

The following command will checkout the specified tag and use docker to build the etcd binaries under /opt/etcd/bin.

```
etcd-manager deploy -user kelsey -tag v2.0.4 \
  -hosts '10.10.0.100:22,10.10.0.101:22,10.10.0.102:22'
```

#### Deploy from a git commit

The following command will checkout the specific commit and use docker to build the etcd binaries under /opt/etcd/bin.

```
etcd-manager deploy -user kelsey -commit 6d81009b26b7e10d4f74ef1be0bd05585c2e503f \
  -hosts '10.10.0.100:22,10.10.0.101:22,10.10.0.102:22'
```

#### Deploy using an etcd binary

The following command will deploy the etcd binary to each host under /opt/etcd/bin.

```
etcd-manager deploy -user kelsey -etcd-binary /Users/kelseyhightower/go/src/github.com/coreos/etcd/bin/etcd \
  -hosts '10.10.0.100:22,10.10.0.101:22,10.10.0.102:22'
```
