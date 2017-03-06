capwap certificate requirements
===============================

wtp certificates
----------------

The certificate identifying the WTP must carry extended key usage
OID 1.3.6.1.5.5.7.3.19 (CAPWAP, WTP). Basic constraints should 
carry `CA:FALSE`. Netscape Extension should have `nsCertType = client`
and `nsComment = "CAPWAP WTP"`.
To summarize - when using openssl it is recommended to use the following
extension file:

```
subjectKeyIdentifier = hash
authorityKeyIdentifier=keyid:always,issuer
extendedKeyUsage=clientAuth,1.3.6.1.5.5.7.3.19
basicConstraints = CA:FALSE
nsCertType = client
nsComment = "CAPWAP WTP"
```

The following openssl command can be used to create a new `key` and
`csr` for CAPWAP:

```
# openssl req -nodes -out ${fqdn}.csr -keyout ${fqdn}.key -new -subj "${subj}"

```

To create the respective certificate on the CA-side you can use
(wtp-ext is the extension file mentioned above):

```
openssl x509 -sha256 -extfile wtp-ext \
	-in ${fqdn}.csr \
	-out ${fqdn}.crt \
	-req -CA ${ca}.crt -CAkey ${ca}.key -CAserial ${ca}.srl \
	-days ${days-30}

```

ac certificates
---------------

In contrast to the wtp certificate requirements the AC-certificate should
carry the extended key usage attribute `1.3.6.1.5.5.7.3.18` and
`nsCertType = server`.
