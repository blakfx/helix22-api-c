#ifndef BLAKFX_HELIX_BASIC_TYPES_H
#define BLAKFX_HELIX_BASIC_TYPES_H

#include <stdint.h>


/**
 * Collection of codes indicating memory ownership model Helix caller will be using.
 */
typedef enum __option_t {
    USER_OWNS_MEMORY = 0x0000,                  ///< Helix should not take copy of the supplied (decryption) buffer and use exclusively user supplied one. User takes on responsibility for ensuring the memory remains valid and accessible for the duration of all Helix operations to complete its work involving that memory location. In case of encryption, caller is responsible to deallocate returned memory buffer with encrypted data.
    HELIX_OWNS_MEMORY = 0x0001,                 ///< Helix should take a copy of the supplied (decryption) buffer and will manage its life-cycle internally. Caller is free to destroy original (decryption) inputs at any time. In case of encryption, Helix will own memory used to return (encrypted) outputs - user is responsible to signal to Helix when the contents are eligible for destruction by calling @ref:ConcludeEncryption with promise-id corresponding to original encryption request.
} option_t;

/**
 * Collection of codes indicating possible conditions as result of function invocation.
 */
typedef enum __invokeStatus_t
{
    INVOKE_STATUS_NOT_INITIALIZED = -255,	///< Status code indicating invoked module is not initialized
    INVOKE_IN_INVALID_STATE = -254,		///< Status code indicating invoked module is not ready -- not initialized or shutting down
    INVOKE_INVALID_INSIDE_CALLBACK = -253,	///< Status code indicating provided callback is invalid
    INVOKE_STATUS_BAD_PROMISE_ID = -252,	///< Status code indicating provided promise id is not valid
    INVOKE_STATUS_TIMEOUT = -2,			///< Status code indicating invocation has timeout
    INVOKE_STATUS_FALSE = -1,			///< Status code indicating invocation has failed
    INVOKE_STATUS_TRUE = 0,			///< Status code indicating invocation completed successfully
} invokeStatus_t;


/**
 * Collection of codes indicating state of a promise (result of computation to be completed in the future).
 */
typedef enum __promiseStatusAndFlags_t
{
    PROMISE_INVALID = -254, 	     ///< Promise state is invalid (either corrupted, or one of internal operations exited with code invokeStatus_t::INVOKE_IN_INVALID_STATE
    PROMISE_INFINITE = -1,              ///< Promised work has no timeout for its completion - promise will remain active until task signals completion (ex: daemon services)
    PROMISE_COMPLETE = 0x0001,          ///< Indicated promised computation has been completed
    PROMISE_DESTROY = 0x0002,           ///< Request destruction of the specified promise (release of resources once promise is complete)
    PROMISE_DATA_AVAILABLE = 0x0004,    ///< There is data available for extraction as result of completion of promised work
    PROMISE_EVENT = 0x0008,             ///< N/A
    PROMISE_USER_EVENT = 0x0010,        ///< N/A
    PROMISE_RESULT_ERROR = 0x0020,      ///< Promised work completed with an error
    PROMISE_MEMORY_ALLOCATED = 0x0040,  ///< N/A
    PROMISE_MEMORY_RELEASING = 0x0080,  ///< N/A
    PROMISE_MEMORY_POST_RELEASED_ID = 0x0100, ///< N/A
    PROMISE_ALLOW_RECURSIVE_EVENTS = 0x1000, ///< N/A
    PROMISE_NO_STATUS = 0x2000,         ///< Status of promised work is unknown (most likely work is in progress)
    PROMISE_WAIT_STATUS = 0x4000,       ///< Promised work is in wait status (most likely task is waiting for completion is another sub-task)
    PROMISE_ERROR_UNDEFINED = 0x8000,   ///< Unknown error condition has been detected
} promiseStatusAndFlags_t;


typedef uint64_t PROMISE_ID;
typedef PROMISE_ID KEY_ID;
typedef PROMISE_ID USER_ID;
typedef PROMISE_ID ENCRYPT_ID;
typedef PROMISE_ID DECRYPT_ID; 

//static uint64_t LOCAL_USER_ID = 0xffffffff;

//static int SERVER_DELAY_RESPONSE_TIME = 4500;   ///< Default maximum tolerable delay for key-server to respond for any requested operation


/**
 * Collection of code values key-server could respond with after various requests.
 */
typedef enum __serverResponseCode_t {
        SERVER_SUCCESS = 0,   ///< Server successfully completed requested action by the client
        SERVER_FAIL = -1,     ///< Server failed to complete requested action by the client
} serverResponseCode_t;


/** 
 * Collection of log-level modes Helix module has.
 */
typedef enum __logLevel_t
{
        NO_LOG = 0x00,       ///< Disable all logging inside Helix module
        ERROR_LEVEL = 0x01,  ///< Enable logging of serious error conditions
        INFO_LEVEL = 0x02,   ///< Enable logging of information-level messages
        WARN_LEVEL = 0x04,   ///< Enable logging of warning messages
        DEBUG_LEVEL = 0x06,  ///< Enable logging of debug-level messages
        ALL_LEVEL = 0xffff,  ///< Enable logging of all possible messages
} logLevel_t;


#endif //BLAKFX_HELIX_BASIC_TYPES_H