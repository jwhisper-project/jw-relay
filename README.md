# JWhisper Relay Server

JWhisper Relay Server is a part of JWhisper platform, providing a relay server users connect to.
It's used mainly to redirect messages between end users, being unable to read users' messages.

## Prerequisites

To run the app you need to have `JDK 25+` installed.

To build the app from sources you will also need some modern version of `Maven 3.X` installed.

## Build

To build the app use the next command:
```bash
mvn clean package
```

Output is the `.zip` file in `target` folder.
Unpack the ZIP archive where you want the app to live.

Done!

## Run

### First initialization

Before the first run you need to provide SSL certificate to be used for TLS communication with clients.

For that you should put it to the `identity.p12` keystore file under any alias you want,
it just should be the only certificate entry in the key store.

If you don't have an SSL certificate for your server, you can create it together with key store using the next command:
```bash
keytool -genkeypair -alias server_key -keyalg RSA -keysize 2048 -validity 365 -keystore identity.p12 -storetype pkcs12
```

Check that the key store was created successfully:
```bash
keytool -list -rfc -keystore identity.p12
```

Save this certificate string (in PEM format) for future (alternatively as file), the clients will need it.
Also remember the password you used for key store, you will need it later to start the server.

### Before run

Before real run you should provide next values:

- `DB_USER_USERNAME` (by default `sa`) - database user username
- `DB_FILE_PASSWORD` - database file password
- `DB_USER_PASSWORD` - database user password
- `SERVER_PASSWORD` - identity keystore password
- `SERVER_PORT` (by default `8443`) - server port

You can provide them as environment variables.
It's the best way to make these values unretrievable.
Without providing them the server can not start.

### Real run

To run the app execute the next command:
```bash
java -jar jw-relay-2.0.0.jar
```

Congratulations! Server is running and is ready for incoming connections.

If you want to stop the server, use `Ctrl + C` hotkey in terminal.

## Users database

In the `./db/` folder the H2 database files will be created.
Users data such as username, public keys (signing and encryption) and registration time are stored in the database.
The entire database is encrypted.

## Developer docs

To build the `javadoc` you can use the next command:
```bash
mvn clean javadoc:aggregate
```
