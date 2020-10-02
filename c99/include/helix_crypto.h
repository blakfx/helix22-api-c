#ifndef HELIX_C99_CRYPTO_H
#define HELIX_C99_CRYPTO_H

#include "helix_types.h"
#include <stdlib.h>


// MODULE LIFECYCLE API: START, LOAD, CONNECT, SHUTDOWN
/**
*	\brief Starts the Helix API module
*       Helix module is composed of various components that will be loaded/activated on demand by the caller. This allows clients of
*       Helix to minimize the start-time, optimize resource utilization, and segment Helix usage by various differentiating factors.
*	@param[in] serverIP the IP/hostname of the Helix Key Server to connect to
*	@param[in] port the port of the Helix Key Server to connect to
*	@param[in] flags additional flags
*	\return result of startup operation
*/
invokeStatus_t blakfx_helix_apiStartup(const char *serverIP, uint16_t port, int64_t flags );

/**
*	\brief Starts the Helix API module, with more options available
*	@param[in] serverIP the IP/hostname of the Helix Key Server to connect to
*	@param[in] port the port of the Helix Key Server to connect to
*	@param[in] customDUID a fake custom device UID
*	@param[in] flags additional flags
*	@param[in] reserved unused
*	\return result of startup operation
*/
invokeStatus_t blakfx_helix_apiStartup_Advanced(const char * serverIP, uint16_t port, const char * customDUID, 
						int64_t flags, void * reserved );

/**
*	\brief Connect to previously specified (see ::blakfx_helix_apiStartup ) Helix key-server.
*       Helix module publishes and exchanges public cryptographic keys with its key-server, in order to facilitate 
*       cryptographically secure End-to-End communication.
*	\return Status of attempt to establish connection with key-server
*/
invokeStatus_t blakfx_helix_serverConnect( void );

/**
*	\brief Sever active connection to Helix key-server
*       Helix operates numerous background tasks allowing clients to complete complex cryptographic operations seamlessly. 
*       To prevent unlikely but possible corruption, it is crucial for Helix users to allow Helix module to complete orderly 
*       disconnect from its key-server.
*	\return Status of severing the connection to the key-server (normal or with errors)
*/
invokeStatus_t blakfx_helix_serverDisconnect(void);

/**
*	\brief Checks whether connection to previously defined key-server is alive (in valid state and responsive).
*       This method is added for posterity, however avoid overusing it or placing it in your execution critical path - it's 
*       execution is network-bound. Under normal circumstances, it safe to assume the connection is active, and check for error
*       conditions of Helix API calls in the critical-path.
*       This method is appropriate for use as connectivity test after long period is inactivity. In all other situations - use 
*       of this API is superfluous and suboptimal.
*	\return Status of connection to previously defined key-server
*/
invokeStatus_t blakfx_helix_serverIsConnected( void );

/**
*	\brief Shut down/cleanup of Helix API module
*       Helix module does a great deal of background work: key-generation, communication with key-server, in addition to
*       asynchronous encryption and decryption processes.
*       It is imperative to allow Helix module to step through orderly shutdown process in order to prevent unlikely but 
*   possible local-data corruption.
*/
void blakfx_helix_apiShutdown(void);


// ACTION MANAGMENT API: EVENTS, STATUSES, CALLBACKS
/**
*	\brief Waits for an event for a specific time
*	@param[in] crypto_ID the ID of the event to wait for
*	@param[in] time_in_ms the time in ms to wait for
*	\return result of the wait operation
*/
invokeStatus_t blakfx_helix_waitEvent(PROMISE_ID crypto_ID, int64_t time_in_ms);

/**
*	\brief Retrieve status of the promise (referencing a promise to complete some operation) by its unique id
*	@param[in] aPromise_id the unique id of the promise whose status to retrieve
*	\return status code indicating the state of the promised work
*/
promiseStatusAndFlags_t blakfx_helix_waitEventStatus(PROMISE_ID aPromise_id);

/**
*	\brief Get the status of a specific promise
*	@param[in] promise_ID the ID of the promise to get the status of
*	\return status of the promise
*/
promiseStatusAndFlags_t blakfx_helix_cPromiseManager_getStatus( PROMISE_ID promise_ID );


// ACCOUNT MANAGEMENT API: CREATE-LOCAL, LOGIN-LOCAL, FIND-RECIPIENT, VALIDATE-RECIPIENT, DOWNLOAD-RECIPIENT-INFO
/**
*	\brief Creates a new account with a given username.
*		All previously generated keys for the account in local key storage will be deleted.
*	@param[in] userName the username for the account
*	\return result code of the creation operation
*/
invokeStatus_t blakfx_helix_accountCreate( const char * userName );

/**
*	\brief Login to an existing account with a given username
*	@param[in] userName the username for the account
*	\return result code of the login operation
*/
invokeStatus_t blakfx_helix_accountLogin( const char * userName );

/**
*	\brief Deletes a local account with a given username
*	@param[in] userName the username for the account
*	\return result code of the deletion operation
*/
invokeStatus_t blakfx_helix_accountDelete( const char * userName );

/**
*	\brief Search for an account with a given username on the current Helix Key Server
*	@param[in] lookup the username for the target account
*	@param[in] waitInMillis the time in ms to attempt the search in
*	\return result of the search operation
*/
PROMISE_ID blakfx_helix_simpleSearchForRecipientByName(const char * lookup, int64_t waitInMillis);

/**
*	\brief Search for an account with a given email on the current Helix Key Server
*	@param[in] lookup the email address of the target
*	@param[in] waitInMillis the time in ms to attempt the search in
*	\return result of the search operation
*/
PROMISE_ID blakfx_helix_simpleSearchForRecipientByEmail(const char * lookup, int64_t waitInMillis);

/**
*	\brief Get the data for a given user
*	@param[in] promiseID the promiseID to find the data for
*	@param[in] user_data_id the user's data ID
*	@param[out] length the length of the user's data
*	\return data as a void *
*/
void * blakfx_helix_getUserData( PROMISE_ID promise_ID, uint64_t user_data_id, size_t * length );

/**
*	\brief Ensure that an user is valid
*	@param[in] user_id the ID of the user to validate
*	\return result of validation
*/
invokeStatus_t blakfx_helix_userValidate( USER_ID user_id );

/**
*	\brief Release an user
*	@param[in] user_id the ID of the user to release
*	\return result of release
*/
invokeStatus_t blakfx_helix_userRelease( USER_ID user_id );


// CRYPTOGRAPHIC API: ENCRYPTION
/**
*	\brief Start encrypting some content intended for a given target user
*	@param[in] user_id the ID of the target user
*	@param[in] data the content to encrypt
*	@param[in] dataSize the size of the content to encrypt
*	@param[in] password optional password to encrypt with
*	@param[in] fileName optional name/path for file with content to encrypt
*	@param[in] anInvocationOptions additional options
*	\return encryption ID for the ongoing encryption
*/
ENCRYPT_ID blakfx_helix_encryptStart( USER_ID user_id, const void * data, size_t dataSize, const char * password, 
					const char * fileName, option_t anInvocationOptions );

/**
*	\brief Get the result of a given encryption task
*	@param[in] encrypt_id the ID of the encryption to get the result of
*	@param[out] serializedOut buffer to place the result of the encryption
*	@param[out] length the length of the encrypted data
*	@param[in] anInvocationOptions additional options to specify
*	\return result of get operation
*/
invokeStatus_t blakfx_helix_encryptGetOutputData(ENCRYPT_ID encrypt_id, uint8_t ** serializedOut,
						size_t * length, option_t anInvocationOptions );

/**
*	\brief Check whether encrypt output exists
*	@param[in] encrypt_id the ID of the encryption to check
*	\return whether the encryption has any output or not
*/
invokeStatus_t blakfx_helix_encryptOutputExists( ENCRYPT_ID encrypt_id );

/**
*	\brief Conclude/wrap up a given encryption task
*	@param[in] encrypt_id the ID of the encryption to conclude
*	\return whether the task was concluded successfully or not
*/
invokeStatus_t blakfx_helix_encryptConclude( ENCRYPT_ID encrypt_id );

/**
*	\brief Get the serialized payload of a given encryption task
*	@param[in] encrypt_id the ID of the encryption to get the result of
*	@param[out] length the length of the encrypted data
*	\return the serialized payload data
*/
uint8_t * blakfx_helix_encryptPayloadGetSerialized( ENCRYPT_ID encrypt_id, size_t * length );

/**
*	\brief Release the serialized payload of a given encryption task
*	@param[in] encrypt_id the ID of the encryption to release the serialized payload of
*	@param[in] serialized the serialized payload data
*	\return whether the data was released successfully
*/
invokeStatus_t blakfx_helix_encryptPayloadSerializedRelease( ENCRYPT_ID encrypt_id, uint8_t * serialized  );


// CRYPTOGRAPHIC API: DECRYPTION
/**
*	\brief Start decrypting some encrypted blob
*	@param[in] cipherData the encrypted blob
*	@param[in] cipherMessageSize the size of the encrypted blob
*	@param[in] password optional password to decrypt with
*	@param[in] anInvocationOptions additional options to specify
*	\return decryption ID for the ongoing decryption
*/
DECRYPT_ID blakfx_helix_decryptStart( uint8_t * cipherData, size_t cipherMessageSize, const char * password, option_t anInvocationOptions );

/**
*	\brief Get the result of a given decryption task
*	@param[in] decrypt_id the ID of the decryption to get the result of
*	@param[out] data buffer to place the result of the decryption
*	@param[out] length the length of the decrypted data
*	\return result of get operation
*/
invokeStatus_t blakfx_helix_decryptGetOutputData( DECRYPT_ID decrypt_id, uint8_t ** data, size_t * length );

/**
*	\brief Release the serialized payload of a given decryption task
*	@param[in] decrypt_id the ID of the encryption to release the serialized payload of
*	\return whether the data was released successfully
*/
invokeStatus_t blakfx_helix_decryptPayloadSerializedRelease( DECRYPT_ID decrypt_id );

/**
*	\brief Check whether a given decryption task is valid
*	@param[in] encrypt_id the ID of the decryption to verify
*	\return whether the decryption is valid or not
*/
invokeStatus_t blakfx_helix_decryptIsValid( DECRYPT_ID decrypt_id );

// Utility (EXPERIMENTAL, do not use)
/// @private
invokeStatus_t blakfx_helix_apiCreateUID( uint8_t * inputBuffer16Bytes, size_t inputBufferSize );



//// ********	ADVANCED API 	******** ////


/**
 * Declaration of callback function Helix would accept to register it as event handler to execute at completion of select events
 */
typedef int64_t (*blakfx_helix_event_handler_t)(PROMISE_ID promise_ID, promiseStatusAndFlags_t status);


/**!
*	\brief Search for an account with a given username on the current Helix Key Server
*	@param[in] userName the username for the target account
*	@param[out] result the result of the search operation
*	@param[in] blakfx_helix_event_handler_t register custom function to be executed as registered event handler with promise status notification
*	\return promise of found/not found user
*/
PROMISE_ID blakfx_helix_userFindByNameAsPromise(const char * userName, invokeStatus_t * result, 
						blakfx_helix_event_handler_t  promise_notification_function );


/**!
*	\brief Search for an account with a given email on the current Helix Key Server
*	@param[in] emailAddress the email address of the target
*	@param[out] result the result of the search operation
*	@param[in] blakfx_helix_event_handler_t register custom function to be executed as registered event handler with promise status notification
*	\return promise of found/not found user
*/
PROMISE_ID blakfx_helix_userFindByEmailAsPromise(const char * emailAddress, invokeStatus_t * result, 
						blakfx_helix_event_handler_t  promise_notification_function );

/**!
*	\brief Search for an user with a given username on the current Helix Key Server
*	@param[in] userName the name of the target
*	@param[out] result the result of the search operation
*	@param[in] blakfx_helix_event_handler_t register custom function to be executed as registered event handler with promise status notification
*	\return user ID of the found/not found user
*/
USER_ID blakfx_helix_userFindByName(const char * userName, invokeStatus_t * result, 
						blakfx_helix_event_handler_t  crypto_notification_function );

/**!
*	\brief Search for an user with a given email on the current Helix Key Server
*	@param[in] emailAddress the email address of the target
*	@param[out] result the result of the search operation
*	@param[in] blakfx_helix_event_handler_t register custom function to be executed as registered event handler with promise status notification
*	\return user ID of the found/not found user
*/
USER_ID blakfx_helix_userFindByEmail(const char * emailAddress, invokeStatus_t * result, 
						blakfx_helix_event_handler_t  crypto_notification_function );


#endif //HELIX_C99_CRYPTO_H