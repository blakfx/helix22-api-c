/*

Demonstrate use of Helix library, embedded in to a file-based command-line cryptographic utility.
Usage: 
`helix_c99_demo.exe [-h] [-ed] [-s string] [--port=<n>] -u string -i string [-o string] [-p string]`

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

*/

#include "helix_crypto.h"
#include "argtable3.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <stdbool.h>

#if defined (__unix__) || (defined (__APPLE__) && defined (__MACH__))
#	include <unistd.h>
#endif


#define ERROR_NONE 0
#define ERROR_SYNTAX 1
#define ERROR_INPUT_NAME 2
#define ERROR_INPUT_READ 3
#define ERROR_INPUT_READSIZE 4
#define ERROR_INPUT_MALLOC 5
#define ERROR_OUTPUT_NAME 6
#define ERROR_OUTPUT_WRITE 7
#define ERROR_HELIX_MODULE 8
#define ERROR_HELIX_SERVER 9
#define ERROR_HELIX_ACCOUNT_CREATE 10
#define ERROR_HELIX_ACCOUNT_LOGIN 11
#define ERROR_HELIX_ENCRYPT_RECIPIENT 12
#define ERROR_HELIX_ENCRYPT_EMPTY 13
#define ERROR_HELIX_DECRYPT_STATUS 14
#define ERROR_HELIX_DECRYPT_EMPTY 15
#define ERROR_HELIX_DECRYPT_SIZE 16
#define ERROR_HELIX_ACCOUNT 17
#define ERROR_ARGPARSE_INVALID 18

// Forward declarations
void loadHelixModule(const char *, uint16_t, const char *, const char *);
invokeStatus_t connectToHelixKeyServer(void);
int authenticateWithHelixNetwork(const char*);
uint8_t * readBytesFromFile(const char *path, size_t *bytesRead);
uint8_t * encryptFromBytes(const char *, uint8_t *content, size_t len, const char *password, size_t *outBytes);
uint8_t * decryptFromBytes(uint8_t *blob, size_t len, const char *password, size_t *outBytes);
void writeBytesToFile(const char *path, const uint8_t *content, size_t count);
void disconnectFromHelixKeyServer(void);
void unloadHelixModule(void);


// Main
struct arg_lit *help = NULL, *enc = NULL, *dec = NULL;
struct arg_str *in = NULL, *out = NULL, *pass = NULL, *user = NULL, *key_server = NULL, *simulated_id = NULL;
struct arg_int *key_server_port = NULL;
struct arg_end *end = NULL;

const char DEFAULT_KEY_SERVER[128] = "service.blakfx.us";
const uint16_t DEFAULT_KEY_SERVER_PORT = 5567;

/**
	\brief The main function of the demo
*/
int main(int argc, char **argv) {

	// Argument table
	void *argTable[] = {
		help    = arg_litn("h", "help", 0, 1, "display this help and exit"),
		key_server = arg_strn("s", "server", "string", 0, 1, "ip/DNS name of key server (without protocol)"),
		key_server_port = arg_intn(NULL, "port", "<n>", 0, 1, "Key Server port"),
		user	= arg_strn("u", "user", "string", 1, 1, "username"),
		simulated_id	= arg_strn("f", "simulated", "string", 0, 1, "simulated device id to simulate when running the app"),
		enc     = arg_litn("e", "encrypt", 0, 1, "encrypt the contents of the input file"),
		dec     = arg_litn("d", "decrypt", 0, 1, "decrypt the contents of the input file or of the result of the encryption (is encryption is done as well)"),
		in      = arg_strn("i", "input", "string", 1, 1, "input file, can be either plaintext or already encrypted"),
		out     = arg_strn("o", "output", "string", 0, 1, "output base filename - if omitted, it's the same as input but on cwd; in any case, output files will have a \'-(en/de)crypted\' postfix accordingly"),
		pass    = arg_strn("p", "password", "string", 0, 1, "password to use for encryption/decryption"),
		end     = arg_end(20),
	};
	//set default values
	*(key_server->sval) = DEFAULT_KEY_SERVER;
	*(key_server_port->ival) = DEFAULT_KEY_SERVER_PORT;

	int nErrors = 0;
	nErrors = arg_parse(argc,argv,argTable);

	/* special case: '--help' takes precedence over error reporting */
    if (help && help->count > 0)
    {
        printf("Usage: %s", argv[0]);
        arg_print_syntax(stdout, argTable, "\n");
        printf("Demonstrate Helix capabilities in fs-util setting.\n\n");
        arg_print_glossary(stdout, argTable, "  %-25s %s\n");
		arg_freetable(argTable, sizeof(argTable) / sizeof(argTable[0]));
		exit(ERROR_NONE);
    }

	/* If the parser returned any errors then display them and exit */
    if (nErrors > 0)
    {
        /* Display the error details contained in the arg_end struct.*/
        arg_print_errors(stdout, end, argv[0]);
        printf("Try '%s --help' for more information.\n", argv[0]);
		arg_freetable(argTable, sizeof(argTable) / sizeof(argTable[0]));
		exit(ERROR_ARGPARSE_INVALID);
    }

	assert(key_server != NULL); assert(key_server_port != NULL);
	assert(enc != NULL); assert(dec != NULL); assert(user != NULL);
	assert(in != NULL); assert(out != NULL); assert(pass != NULL);

	const char *server_ip = *(key_server->sval);
	const uint16_t server_port = (uint16_t) *(key_server_port->ival);
	const char *username = *(user->sval);
	const char *simulated_device = (simulated_id->count) ? *(simulated_id->sval) : NULL;


	// load and initialise Helix module
	loadHelixModule(server_ip, server_port, username, simulated_device);


	// connect to Helix key-server
	const invokeStatus_t serverConnectionStatus = connectToHelixKeyServer();
	if( INVOKE_STATUS_TRUE != serverConnectionStatus) {
		fprintf(stderr, "Error: helix_serverConnect returned exit code: %d\n", serverConnectionStatus);	
		return ERROR_HELIX_SERVER;
	}

	
	// login to Helix key-server
	int modulePrepStatus = authenticateWithHelixNetwork(username);
	if( 0 != modulePrepStatus) {
		fprintf(stderr, "Error: authenticateWithHelixNetwork returned exit code: %d\n", modulePrepStatus);
		return -1;
	}


	// Parsed args successfully, store them into easy-to-access variables
	bool encrypt = enc->count > 0;
	bool decrypt = dec->count > 0;
	const char *inFile = *(in->sval);
#if defined(_WINDOWS_)
	char *fileBase = strrchr(inFile, '\\'); // Account for windows path separators
#else
	char *fileBase = strrchr(inFile, '/'); // Account for windows path separators
#endif
	fileBase = (fileBase) ? fileBase : (char *)inFile;
	const char *outFile = (out->count) ? *(out->sval) : fileBase + 1;
	const char *password = (pass->count) ? *(pass->sval) : NULL;

	// Prepare encrypted and decrypted paths
	#define MAX_FILEPATH_LENGTH 2048
	char outFileEncrypted[MAX_FILEPATH_LENGTH] = { 0 };	// C does not allow compile-time variables as sizes of stack array declarations 
	char outFileDecrypted[MAX_FILEPATH_LENGTH] = { 0 };
	strcpy(outFileEncrypted, outFile);
	strcat(outFileEncrypted, "-encrypted");
	strcpy(outFileDecrypted, outFile);
	strcat(outFileDecrypted, "-decrypted");

	// Read the byte contents of a given file
	size_t bytesFromFile = 0;
	uint8_t *dataFromFile = readBytesFromFile(inFile, &bytesFromFile);
	fprintf(stdout, "Info: Read data from file (%zu bytes) from input file \'%s\'\n", bytesFromFile, inFile);
	

	//track exit status across encrypt/decrypt operations
	int op_failure = 0;

	// Encrypt plaindata and write it out
	// By default, encrypted = plaindata (before actually trying to encrypt)
	// This allows a user to pass an encrypted file and decrypt it with minor adjustments
	size_t encryptedBytes = 0;
	uint8_t *encrypted = NULL;
	if(encrypt) {
		// sending the message to ourselves now
		encrypted = encryptFromBytes(username, dataFromFile, bytesFromFile, password, &encryptedBytes);
		writeBytesToFile(outFileEncrypted, encrypted, encryptedBytes);
		op_failure |= 0;
		fprintf(stdout, "Info: wrote %zu bytes to \'%s\'\n", encryptedBytes, outFileEncrypted);
	}

	// Decrypt plaindata/content and write it out
	size_t decryptedBytes = 0;
	uint8_t *decrypted = NULL;
	if(!op_failure && decrypt) {		
		if(!encrypt) {
			fprintf(stdout, "Info: main: Calling decrypt on %zu bytes read from encrypted file: \'%s\' into buffer at %p\n", bytesFromFile, inFile, dataFromFile);
			decrypted = decryptFromBytes(dataFromFile, bytesFromFile, password, &decryptedBytes);
		} else {
			fprintf(stdout, "Info: main: Calling decrypt on %zu bytes in memory buffer at %p after encryption is done\n", encryptedBytes, encrypted);
			decrypted = decryptFromBytes(encrypted, encryptedBytes, password, &decryptedBytes);
			// Ensure bytes decrypted count == bytes original count
			if(decryptedBytes != bytesFromFile) {
				fprintf(stderr, "Error: main: byte count between original plaindata (%zu) and decrypted plaindata (%zu) differs\n", encryptedBytes, decryptedBytes);
				op_failure |= ERROR_HELIX_DECRYPT_SIZE;
			}
		}
		// Write out
		fputs("Info: decryption succeeded\n", stdout);
		writeBytesToFile(outFileDecrypted, decrypted, decryptedBytes);
		op_failure |= 0;
		fprintf(stdout, "Info: wrote %zu bytes to \'%s\'\n", decryptedBytes, outFileDecrypted);
	}

	// Note: If these buffers were created with use ot "USER_OWNS_MEMORY" flag, they should be freed here.
	// If they were provided by Helix to caller when invoked with "HELIX_OWNS_MEMORY" -- Helix will managed
	// these reources internally (freeing them explicitely will result in "double-free" errors).
	//free(encrypted); //THIS buffer was allocated with "HELIX_OWNS_MEMORY" flag - it is managed by HELIX library
	//free(decrypted); //THIS buffer was allocated with "HELIX_OWNS_MEMORY" flag - it is managed by HELIX library
	
	free(dataFromFile); //THIS buffer is owned by the user

	fprintf(stdout, "Info: main: Disconnecting from the server\n");
	disconnectFromHelixKeyServer();
	
	fprintf(stdout, "Info: main: Starting shutdown\n");
	unloadHelixModule();
	
	fprintf(stdout, "Info: main: Finished shutdown\n");
	arg_freetable(argTable, sizeof(argTable) / sizeof(argTable[0]));
	
	return op_failure;
}

/**
	\brief Reads bytes from a given file
	@param[in] path the path of the file to read
	@param[out] bytesRead the number of bytes read
	\return the bytes read
*/
uint8_t * readBytesFromFile(const char *path, size_t *bytesRead) {
	size_t expectedBytesFromDisk = 0;
	uint8_t *buf = NULL;
	int error = 0;
	*bytesRead = 0;
	
	// Open the file pointed to by path
	FILE *file = fopen(path, "rb");
	if(file) {
		// Get it's byte count/length
		fseek(file, 0, SEEK_END);
		expectedBytesFromDisk = ftell(file);
		rewind(file);

		// Allocate a buffer for the length to store file contents
		// We deal with data on byte-size level - element is 1 byte = sizeof(uint8_t)
		size_t numofElementsOnDisk = expectedBytesFromDisk * sizeof(uint8_t); // sizeof(uint8_t) is 1
		buf = (uint8_t *)calloc(numofElementsOnDisk, sizeof(uint8_t));
		if(!buf) {
			fprintf(stderr, "Error: could not allocate memory for input file \'%s\'\n", path);
			exit(ERROR_INPUT_MALLOC);
		}

		// Read bytes from the file to buffer
		size_t numOfElementsReadFromDisk = fread(buf, sizeof(uint8_t), numofElementsOnDisk, file);
		
		const size_t bytesReadFromDisk = numOfElementsReadFromDisk * sizeof(uint8_t);
		if(bytesReadFromDisk != expectedBytesFromDisk) {
			fprintf(stderr, "Error: expected %zu bytes but read %zu bytes from input\n", expectedBytesFromDisk, bytesReadFromDisk);
			exit(ERROR_INPUT_READ);
		}
		
		error = ferror(file);
		if(error) {
			fprintf(stderr, "Error: could not read from input file \'%s\' - error %d\n", path, error);
			exit(ERROR_INPUT_READ);
		}
		
		// Success: close file pointer, assign read bytes, and return buffer
		fclose(file);
		*bytesRead = bytesReadFromDisk;
		return buf;
	}
	// Could not open file
	fprintf(stderr, "Error: bad input file name \'%s\'\n", path);
	exit(ERROR_INPUT_NAME);
}

/**
	\brief Writes bytes to a file
	@param[in] path the path of the file to write to
	@param[in] content the bytes to write
	@param[in] count the number of bytes to write
*/
void writeBytesToFile(const char *path, const uint8_t *content, size_t count) {
	// Open the file pointed to by path
	FILE *file = fopen(path, "w+b");
	if(file) {
		// Write the content into the file
		if(fwrite((void *)content, sizeof(uint8_t), count, file) == count) {
			fclose(file);
		}
		else {
			fprintf(stderr, "Error: could not write to output file \'%s\'\n", path);
			exit(ERROR_OUTPUT_WRITE);
		}
	}
	// Could not open file
	else {
		fprintf(stderr, "Error: bad output file name \'%s\'\n", path);
		exit(ERROR_OUTPUT_NAME);
	}
}

/**
	\brief Internal helper method to handle account creation
	@param[in] account name of the account to create
	\return whether creation succeeded or not
*/
bool accountCreate(const char *account) {
	fprintf(stdout, "Info: attempting to create account with name %s\n", account);
	uint64_t createResult = blakfx_helix_accountCreate(account);
	if(createResult != 0) {
		fprintf(stderr, "Warn: helix_accountLocalNew returned exit code: %"PRIu64"\n", createResult);
		return false;
	}
	fprintf(stdout, "Info: account creation of name %s succeeded\n", account);
	return true;
}

/**
	\brief Internal helper method to handle account login
	@param[in] account name of the account to log into
	\return whether account login succeeded or not
*/
bool accountLogin(const char *account) {
	fprintf(stdout, "Info: attempting to login to account with name %s\n", account);
	uint64_t loginResult = blakfx_helix_accountLogin(account);
	if(loginResult != 0) {
		fprintf(stderr, "Warn: helix_accountLocalLogin returned exit code: %"PRIu64"\n", loginResult);
		return false;
	}
	fprintf(stdout, "Info: account login of name %s succeeded\n", account);
	return true;
}

/**
	\brief Internal helper method to handle account deletion
	@param[in] account name of the account to delete
	\return whether account deletion succeeded or not
*/
bool accountDelete(const char *account) {
	fprintf(stdout, "Info: attempting to delete account with name %s\n", account);
	uint64_t deleteResult = blakfx_helix_accountDelete(account);
	if(deleteResult != 0) {
		fprintf(stderr, "Warn: helix_accountLocalDelete returned exit code: %"PRIu64"\n", deleteResult);
		return false;
	}
	fprintf(stdout, "Info: account deleteion of name %s succeeded\n", account);
	return true;
}


/*
	\brief Load helix module into process memory and initialise its runtime state.
	@param[in] server_ip the ip of the Helix key server to connect to
	@param[in] server_port the port of the Helix key server to connect to
	@param[in] account the account name to identify as
	@param[in] device the emulated device to connect with (real device if NULL)
*/
void loadHelixModule(const char *server_ip, uint16_t server_port, const char *account, const char *device) {
	assert( server_ip != NULL && strlen(server_ip) > 0 && strlen(server_ip) < 128);
	assert( server_port > 0 && server_port < 65535);
	assert( account != NULL && strlen(account) > 0);

	// Start up the module, either with real or simulated device
	if(device) {
		fprintf(stdout, "Info: starting up Helix module with simulated device %s for user %s\n", device, account);

		// Run the advanced startup for the module with this simulated device
		const invokeStatus_t loadStatus = blakfx_helix_apiStartup_Advanced(server_ip, server_port, (char *)device, 0, NULL);
		if( INVOKE_STATUS_TRUE != loadStatus) {
			fprintf(stderr, "Error: helix_apiStartupAdvanced returned exit code: %d\n", loadStatus);
	    	exit(ERROR_HELIX_MODULE);
		}
	}
	else {
		// Run with this genuine device
		fprintf(stdout, "Info: starting up Helix module with real device for user %s\n", account);
		const invokeStatus_t loadStatus = blakfx_helix_apiStartup(server_ip, server_port, 0);
		if( INVOKE_STATUS_TRUE != loadStatus) {
			fprintf(stderr, "Error: helix_apiStartup returned exit code: %d\n", loadStatus);
			exit(ERROR_HELIX_MODULE);
		}
	}
}


/**
	\brief Unload Helix Module.
	This call disables all Helix module actitivies and delete its runtime state from memory.
*/
void unloadHelixModule(void) {
	blakfx_helix_apiShutdown();
}

/**
	\brief Connect to Helix key-server (that was specified at Helix initialization time).
	\return result status of the connection attempt
*/
invokeStatus_t connectToHelixKeyServer(void) {	
	const invokeStatus_t serverConnectionStatus = blakfx_helix_serverConnect();
	return serverConnectionStatus;
}

/**
	\brief Disconnect from Helix key-server. 
	This is a blocking call - its return signals orderly discontinuity of all network activities.
*/
void disconnectFromHelixKeyServer(void) {
	blakfx_helix_serverDisconnect();
}


/**
	\brief Perform authentication (of existing) or creation (of new) account in Helix Network.
	@param[in] account the account name to identify as
	\return result of user authentication attempt
*/
int authenticateWithHelixNetwork(const char *account) {
	assert( account != NULL && strlen(account) > 0);
	int exit_code = -1;
	
	// Search for recipient/target (in this case, oneself)
	// attempt to login to it
	uint64_t loginResult = accountLogin(account);
	if(!loginResult) {
		// Login failed, delete account and recreate it
		accountDelete(account);
		
		// Regardless whether delete failed/succeeded, attempt to create a new account
		uint64_t createResult = accountCreate(account);
		if(!createResult) {
			// Create failed, fatal error
			exit_code = -30;
		}
		else {
			// Create succeded, login to it
			loginResult = accountLogin(account);
			if(!loginResult) {
				// Login failed, fatal error
				exit_code = -40;
			}
			else {
				// Login succeeded, we're done
				exit_code = 0;
			}
		}
	} else {
		// Login succeeded, we're done
		exit_code = 0;
	}

	return exit_code;
}

/**
	\brief Given some plain content, encrypt it for a given target user
	@param[in] recipientAccount the name of the target to encrypt this message for
	@param[in] content the content to encrypt
	@param[in] len the size of the content to encrypt
	@param[in] password the password to encrypt the content with
	@param[out] outBytes the number of bytes of the encryption result
	\return the encrypted bytes result
*/
uint8_t * encryptFromBytes(const char *recipientAccount, uint8_t *content, size_t len, const char *password, size_t *outBytes) {
	fprintf(stdout, "Info: encrypt: Attempting to encrypt %zu bytes with password %s\n", len, password);
	
	*outBytes = 0;
	uint8_t *result = NULL;
	assert(recipientAccount != NULL);
	
	// Attempt to find recipient
	int64_t msWait = 5000;
	const PROMISE_ID recipientID = blakfx_helix_simpleSearchForRecipientByName(recipientAccount, msWait);
	fprintf(stdout, "Info: encrypt: search for user [%s] returned promise: %"PRIu64"\n", recipientAccount, recipientID);
	const promiseStatusAndFlags_t foundRecipient = blakfx_helix_waitEventStatus(recipientID);
	if(PROMISE_DATA_AVAILABLE != foundRecipient ) {
		fprintf(stderr, "Error: encrypt: could not find test account - got code %d\n", foundRecipient);
		exit(ERROR_HELIX_ENCRYPT_RECIPIENT);
	}
		
	fprintf(stdout, "Info: encrypt: Attempting to get encryption handle to work on %p, guarded by promise: %"PRIi64"\n", content, recipientID);
	// Get encryption handle
	const uint64_t encryptionHandle = blakfx_helix_encryptStart(recipientID, (void *)content, len, (char *)password, NULL, HELIX_OWNS_MEMORY);
	fprintf(stdout, "Info: encrypt: Got encryption handle %"PRIu64" for promise: %"PRIi64"\n", encryptionHandle, recipientID);

	const promiseStatusAndFlags_t encryptionDone = blakfx_helix_waitEvent(encryptionHandle, PROMISE_INFINITE);
	fprintf(stdout, "Info: encrypt: Encryption finished, handle: %"PRIu64" returned action code: %d\n", encryptionHandle, encryptionDone);
	
	// Encrypt the data
	const promiseStatusAndFlags_t foundValidEncryptedData = blakfx_helix_waitEventStatus(encryptionHandle);
	fprintf(stdout, "Info: encrypt: Starting to retrieve encrypted data after getting validation code: %d\n", foundValidEncryptedData);
	if( PROMISE_DATA_AVAILABLE != foundValidEncryptedData ) {
		fprintf(stderr, "Error: encrypt: encryption completed but returned error code: %d\n", foundValidEncryptedData);
		exit(ERROR_HELIX_ENCRYPT_EMPTY);
	}
	
	// HELIX owns returned buffer, it will destroy it, when "encryptConclude" is called with handle_id
	size_t dataSize = 0;
	const invokeStatus_t retrievalStatus = blakfx_helix_encryptGetOutputData(encryptionHandle, &result, &dataSize, HELIX_OWNS_MEMORY); //or USER_OWNS_MEMORY
	if(result && dataSize > 0) {
		fprintf(stdout, "Info: encrypt: Encryption succeeded - returning blob at %p of length %zu bytes with status %d\n", result, dataSize, retrievalStatus);
		*outBytes = dataSize;
	}
	
	// NOTE: if above call "blakfx_helix_encryptGetOutputData" used flag "USER_OWNS_MEMORY",
	// caller MUST take ownership of the memory associated with returned handle_id (encryptionHandle),
	// and signal to Helix library (by invoking "blakfx_helix_encryptConclude") to 
	// release internal resources associated with the handle-id (encryptionHandle).
	// Otherwise, a logical resource leak will occur.
	//
	//const invokeStatus_t encCleanUp = blakfx_helix_encryptConclude(encryptionHandle);
	//fprintf(stdout, "Info: encrypt: Concluded encryption operation with code: %d\n", encCleanUp);

	return result;
}

/**
	\brief Given some encrypted content, decrypt it
	@param[in] blob the encrypted content to decrypt
	@param[in] len the size of the content to decrypt
	@param[in] password the password to use when decrypting the content
	@param[out] outBytes the number of bytes of the decryption result
	\return the decrypted bytes result
*/
uint8_t * decryptFromBytes(uint8_t *blob, size_t len, const char *password, size_t *outBytes) {
	fprintf(stdout, "Info: decrypt: Attempting to decrypt %zu bytes with password %s\n", len, password);
	
	*outBytes = 0;
	uint8_t *result = NULL;
	
	// Get decryption handle
	fprintf(stdout, "Info: decrypt: Attempting to get decryption handle, for buffer at %p, with byte-size %zu\n", blob, len);
	// HELIX will NOT take copy of the supplied buffer - it MUST remain valid until decrypt operation completes
	const ENCRYPT_ID decryptionHandle = blakfx_helix_decryptStart(blob, len, (char *)password, USER_OWNS_MEMORY);
	fprintf(stdout, "Info: decrypt: Got decryption handle: %"PRIu64"\n", decryptionHandle);

	const invokeStatus_t decryptionStatus = blakfx_helix_waitEvent(decryptionHandle, PROMISE_INFINITE);
	fprintf(stdout, "Info: decrypt: Decryption finished: handle %"PRIi64" returned action code %d\n", decryptionHandle, decryptionStatus);


	// Decrypt the data
	promiseStatusAndFlags_t foundValidDecryptedData = blakfx_helix_waitEventStatus(decryptionHandle);
	if(PROMISE_DATA_AVAILABLE != foundValidDecryptedData) {
		fprintf(stderr, "Error: decrypt: could not retrieve decrypted data successfully, code: %d\n", foundValidDecryptedData);
		exit(ERROR_HELIX_DECRYPT_STATUS);
	}
	
	size_t dataSize = 0;
	const invokeStatus_t retrievalStatus = blakfx_helix_decryptGetOutputData(decryptionHandle, &result, &dataSize);
	if(result && dataSize > 0) {
		fprintf(stdout, "Info: decrypt: Decryption completed - returning blob at %p of length %zu bytes with status: %d\n", result, dataSize, retrievalStatus);
		*outBytes = dataSize;
	}
	
	return result;
}

