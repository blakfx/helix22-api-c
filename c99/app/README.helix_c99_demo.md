Command-Line Encrypt/Decrypt utility using Helix Library 
========================================================

## Synopsys
Demonstrate use of Helix library, embedded in to a file-based command-line cryptographic utility.
Usage: 
`helix_c99_demo [-h] [-ed] [-s string] [--port=<n>] -u string -i string [-o string] [-p string]`

  -h, --help                display this help and exit
  -s, --server=string       ip/DNS name of key server, without protocol (optional, if licensed)
  --port=<n>                Key Server port
  -u, --user=string         username
  -e, --encrypt             encrypt the contents of the input file
  -d, --decrypt             decrypt the contents of the input file or of the result of the encryption (is encryption is done as well)
  -i, --input=string        filepath of input file; file could be either plaintext or already encrypted (for decryption step)
  -o, --output=string       start of filename for the output file - if omitted, input filename will be used; all output files will have a '-(en/de)crypted' postfix appended
  -p, --password=string     password to use for encryption/decryption (optional)


Server and port arguments are optional, if distributed by BlakFx along with the utility.
Do not use these parameters, if you are not supplied with this information (ex: evaluation or demo usage).

Username is an artitrary string of characters (no spaces allowed). 
It will be used to create new or resume existing key sessions.

Generated files with encrypted contents will have "-encrypted" appended to the original filename. 
For example, encrypted output of `my_text.txt` will be saved as `my_text.txt-encrypted`.

Generated files with decrypted contents will have "-decrypted" appended to the original filename.
For example, decrypted output of `my_text.txt` will be saved as `my_text.txt-decrypted`.
