# sned
sned is an end-to-end encrypted platform for transferring files between users. sned uses the [sodiumoxide](https://docs.rs/sodiumoxide/0.2.6) library for encryption/authentication/signatures. This repository is the client component of the app, the server component is located at [sned-server](https://github.com/hmir/sned-server).

## Usage
The repository provides a CLI for interacting with a sned server and encrypting/decrypting files. The following subcommands are available. 

### `register`
`sned register <username> <server>`

This command attempts to register a user of name `<username>` at the server located at `<server>` (which can be an IP address or URL). To set up a sned server, consult https://github.com/hmir/sned-server

Two key-pairs are locally generated using the [sodiumoxide box](https://docs.rs/sodiumoxide/0.2.6/sodiumoxide/crypto/box_/index.html) and [sodiumoxide sign](https://docs.rs/sodiumoxide/0.2.6/sodiumoxide/crypto/sign_/index.html) modules, respectively, which are associated with the new user for the server. The public keys are sent to the server.

Once register executes successfully, `<server>` and `<username>` will be configured as the "current server" and "current username" and will be remembered for subsequent calls to commands like `transfer` and `download`. The change the current server/username, use `ch-server`.

Example usage:

`sned register alice 192.168.1.105` 
(registers username "alice" at the server located at 192.168.1.105)

### `list-users`
`sned list-users`

Query the current server for the usernames of all its registered users.

### `transfer`
`sned transfer [-n <name>] <file> <recipient_0> <recipient_1> <recipient_2> ... `

Upload the file specified by `<file>` to the current server, intended for download by the recipients specified. The command accepts an arbitrary number of recipients, but at least one is required. Optionally, the transfer can be given a name using the `-n` option. 

The file is encrypted with a symmetric key generated using the [libsodium secretstream](https://docs.rs/sodiumoxide/0.2.6/sodiumoxide/crypto/secretstream/index.html) module. The public key of each recipient is used to encrypt this symmetric key before it is sent to the server, ensuring that the intended recipients can decrypt the file, but not the server.


Example usage:

`sned transfer -n "Sample file" ./textfiles/file.txt bob alice ` (uploads file located at ./textfiles/file.txt, to be downloaded by bob and alice) 

### `inbox`
`sned inbox`

Outputs a table of all the files that are available for download by the user (i.e. files which have been sent to the user using `sned transfer`) at the current server.

### `download`
`sned download <id> <file>`

Downloads and decrypts a file with id `<id>` from the current server to the location specified by `<file>`. The id's of files that can be downloaded can be listed using `sned inbox`. 

Example usage:

`sned download 4 ./output.txt` (download file with id `4` to  `./output.txt`)

### `whoami`
`sned whoami`

This command will list the current username, current server, and current public key (as a base64 string). To change servers use `ch-server`

### `lookup`
`sned lookup <username>`

Query the current server for the public key corresponding the user with the provided username, and output it as a base64 string.

This command offers an out-of-band method to ensure that the server is not acting maliciously. The public key returned by `lookup` should be compared to the queried user's output of `whoami` to ensure the public keys match.

### `list-servers`
`sned list-servers`

List the servers that have been registered on this machine.

### `ch-server`
`sned ch-server <server>`

Switch the current to server to the one specified by `<server>`.

Example usage:

`sned ch-server 192.168.1.5` (switch the current server to 192.168.1.5)

## Disclaimer
This project was built for educational purposes only. The developer(s) do not take responsibility for any data that is lost or stolen while using the app.

