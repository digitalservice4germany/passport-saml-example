# SAML Example for EKONA integration

This node.js web application demonstrates SSO authentication via EKONA (ELSTER Login), using the `passport-saml` package.

## Config

Copy `.env.sample` or `.env.sample.dev` to `.env` and edit it appropriately. Use the dev configuration if you are working with the test environment of EKONA (Testumgebung).

This app requires 3 files to be placed in a folder named `cert` located in the project's root directory. These files include (1) the certificate of the Identity Provider (IdP). As a Service Provider (SP), you need to generate your own (2) certificate and (3) private key.
These files are named as follows:

- `idp_cert.pem`: IdP's certificate (EKONA certificates can be downloaded [here](https://service.mein-unternehmensportal.de/dokumente) unter "Technikpaket für Integrationspartner")
- `sp_cert.pem`: SP's certificate (Generated by you)
- `sp_key.pem`: SP's private key (Generated by you)

Note: Use the certificates provided in LastPass under `Shared Grundsteuer > EKONA -SAML Example App` or generate new ones as described below.

## Creating Private Key and Certificates

Generate public and private keys using Java's `keytool`:

- Generate a keystore which contains a certificate and private key (Note: keysize must be at least 4096 bit)
    ```
    keytool -genkey -alias sp -dname "CN=my-application.de, C=DE" -keystore sp.keystore -keyalg RSA -validity 360 -keysize 4096
    ```
- Export the certificate (public key) from the keystore
    ```
    keytool -export -rfc -keystore sp.keystore -alias sp -file sp_cert.pem
    ```
- Convert the keystore to the PKCS12 format to be able to export the private key
    ```
    keytool -v -importkeystore -srckeystore sp.keystore -srcalias sp -destkeystore sp.p12 -deststoretype PKCS12
    ```
- Export the private key from the keystore
    ```
    openssl pkcs12 -in sp.p12 -nocerts -nodes > sp_key.pem
    ```

## Registering the Service Provider

The Service Provider must be configured via the [Self Service Portal](https://service.mein-unternehmensportal.de/). Make sure to configure the following:

- **Name**: enter any name
- **Entity-ID**: choose a unique name which is the same as the `ISSUER` in your `.env` (e.g. the url of your application)
- **Datenkranztyp**: choose "AO"
- **Kontotyp**: choose "Echt" (even if it's your DEV environment!)
- **Zum Login zugelassene(s) Ordnungsmerkmal(e)**: Choose "IdNr"
- **Portalbeschreibung bzw. angezeigte Beschreibung**: enter any description (Attention: The description must not include special characters) 
- **Portal-Logo**: upload any logo
- **Signaturzertifikat**: enter the Service Provider public key which you generated
- **Verschlüsselungszertifikat**: enter the Service Provider public key which you generated
- **Assertion Consumer Service URLs**: enter the callback URL where EKONA sends the requests to (must be the `CALLBACK_URL` from your `.env`)
- **Manage Name ID URLs**: optional - leave empty

## Usage

```
npm install
npm start
```

