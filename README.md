# Hardware Security Module (HSM) Online Certificate Status Protocol (OCSP)

This go module supports the creation of an ocsp server that is capable of using a PKCS#11 HSM, such as the [NitroKey HSM](https://shop.nitrokey.com/shop/product/nk-hsm-2-nitrokey-hsm-2-7), as the signer for the ocsp responder.  When properly configured, the hsmocsp server will return a signed response signifying that the certificate specified in the request is 'good', 'revoked', or 'unknown'. If it cannot process the request, it will return an error code.

## Supported Certificate Sources

The hsmocsp server currently supports two source types which implement the [cfssl ocsp responder interface](https://github.com/cloudflare/cfssl/blob/master/ocsp/responder.go) to validate certificates; additional support for cfssl certdb and response file sources could likely easily be added.

|  Source Type  |                         Description                         |
|---------------|-------------------------------------------------------------|
|[OpenSslSource](https://github.com/spyd3rweb/hsmocsp)|Uses the [OpenSSL](https://github.com/openssl/openssl) ca db and crl files; optionally supports hosting ca issuer and crl static files
|[VaultSource](https://github.com/T-Systems-MMS/vault-ocsp)|Uses the [Vault PKI Engine](https://www.vaultproject.io/docs/secrets/pki) ca and crl urls and cert api|

# Deployment
## [app-hsmocsp](https://github.com/spyd3rweb/app-hsmocsp) is a [cloud-native application](https://cloud.google.com/blog/products/application-development/kubernetes-development-simplified-skaffold-is-now-ga) with [kubectl](https://skaffold.dev/docs/pipeline-stages/deployers/kubectl/) and [Helm](https://skaffold.dev/docs/pipeline-stages/deployers/helm/) deployments for this hsmocsp go module
In addition to the app-hsmocsp container, the provided dev and debug [skaffold profiles](https://skaffold.dev/docs/environment/profiles/) will also deploy the app-pki container, which uses a helper script to create a working PKCS#11 HSM PKI environment *for development purposes only*; it includes configurable steps to automatically validate and initialize:
* Certificates and Keypairs for the [OpenSSL Root CA](https://www.openssl.org/docs/man1.0.2/man1/ca.html)
* Vault PKI Secrets engines and intermediate CA certificates properly signed and chained with the OpenSSL ca-keypair
* Keypairs for OCSP server certificates for both OpenSSL and Vault CA sources for app-hsmocsp to consume

|PKI Level| Cert |HSM Key|Vault Key|File Key|
|--------|:-----|:-----:|:-------:|:------:|
|1|OpenSSL CA|x|||                  
|1|OpenSSL CA OCSP|x|||                  
|2|Vault Root CA||x||    
|2|Vault Root CA OCSP|x|||                
|3|Vault Int Dev CA||x||
|3|Vault Int Dev CA OCSP|x|||
|3|Vault Int Dev CA Client|||x|                         
