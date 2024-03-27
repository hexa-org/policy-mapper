![Hexa](https://hexaorchestration.org/wp-content/themes/hexa/img/logo.svg)

# Example: OPA-Server Integration

This directory shows an example of deploying a HexaOPA server along with an OPA Bundle server (see [docker-compose.yml](docker-compose.yml)).

> [!Note]
> The opa server and bundle server will automatically look for certificates in the `.certs` sub-directory. If not found,
> the `hexa-bundle-server` service will auto-generate self-signed keys. This allows the `hexa-opa-server` to set up
> a TLS connection to the bundle server.

The configuration for the OPA server is defined in [config.yaml](config/config.yaml). This causes the OPA server to load
bundles from the hexa-bundle-server.

To test with the Hexa CLI tool, use a bundle url of https://127.0.0.1:8889 and reference the `ca_cert.pem` in `.certs`. For example:

```shell
hexa add opa http myBundle --url="https://hexa-bundle-server:8889" --cafile="./examples/opa-server/.certs/ca-cert.pem"
```

> [!Tip]
> You may need to update your /etc/hosts file to define hexa-bundle-server as 127.0.0.1

Finally, you will want to set up an application that queries the hexaOpa server for policy decisions. For more information,
see the [Hexa Policy-OPA](https://github.com/hexa-org/policy-opa) project.
