# vt-houdini

Prototype.


## Running this:

### Make a host key

Generate:

```
ssh-keygen -t ed25519 -f host_key -N ''
```

### Build it

```
go build ./cmd/vtest-server
```

### Run it

```
./vtest-server -listen :2222
```

Then: `ssh -p 2222 localhost`

## License
AGPL-3.0-or-later
https://www.gnu.org/licenses/agpl-3.0.txt
