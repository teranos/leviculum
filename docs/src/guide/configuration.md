# Configuration

Leviculum reads the same INI-style configuration file as Python Reticulum, located at `~/.reticulum/config` by default.

Use `--config` to specify an alternative configuration directory.

## Example

```ini
[reticulum]
  enable_transport = yes
  share_instance = yes

[interfaces]
  [[Default Interface]]
    type = AutoInterface
    enabled = yes
```

See the [Reticulum documentation](https://reticulum.network/manual/) for the full configuration reference. Leviculum accepts the same options.
