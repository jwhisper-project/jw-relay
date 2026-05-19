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

If you don't have a SSL certificate for your server, you can create it together with key store using the next command:
```bash
keytool -genkeypair -alias server_key -keyalg RSA -keysize 2048 -validity 365 -keystore identity.p12 -storetype pkcs12
```

Check that the key store was created successfully:
```bash
keytool -list -rfc -keystore identity.p12
```

Save this certificate string (in PEM format) for future, the clients will need it.
Also remember the password you used for key store, you will be prompted to enter it when
starting relay server.

### Real run

To run the app execute the next command:
```bash
java -jar jw-relay-1.0.0.jar
```

If you are running the server for the first time, you will be prompted to enter server details such as `port`.
These details will be saved to `config.json` file, where you are free to change them in the future.

Congratulations! Server is running and is ready for incoming connections.

If you want to stop the server, use `Ctrl + C` hotkey in terminal.

## Developer docs

To build the `javadoc` you can use the next command:
```bash
mvn clean javadoc:aggregate
```
