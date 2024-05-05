#pragma once

#include "static_from_file.h"


// Static inclusion of data.
// Data is formatted as array and written into the static_data.include file by the set_*_source function.
// This function wraps static_from_file, as the prodecure is the same.
//
// arg1 specifies which array the data is read from.
// data_size receives the size of the data in bytes.
unsigned char *static_from_here(char *arg1, int *data_size) {
        #ifdef STATIC_PAYLOAD
    if(strcmp(arg1, "static_payload") == 0) {
        DEBUG_PRINT("Statically retrieving data from array buf[] in included file...\n");
        *data_size = sizeof(buf) - 1;	
        return buf;
    }
    #endif
    // Deliver address and size of array key[] if key is requested
    // If the key is retrieved statically, the define is set by the build script to notify this function that array key[] is declared and known to the compiler.
    #ifdef STATIC_KEY     
    if(strcmp(arg1, "static_key") == 0) {
        DEBUG_PRINT("Statically retrieving data from array key[] in included file...\n");
        *data_size = sizeof(key) - 1;	
        return key;
    }
    #endif
    // Deliver address and size of array payload_info[] if payload info is requested
    // If payload info is retrieved statically, the define is set by the build script to notify this function that array payload_info[] is declared and known to the compiler.
    #ifdef STATIC_PAYLOAD_INFO
    if(strcmp(arg1, "static_payload_info") == 0) {
        DEBUG_PRINT("Statically retrieving data from array payload_info[] in included file...\n");
        *data_size = sizeof(payload_info) - 1;
        return payload_info;
    }   
    #endif
    // Deliver address and size of array command[] if command is requested
    // If command is retrieved statically, the define is set by the build script to notify this function that array command[] is declared and known to the compiler.
    #ifdef STATIC_COMMAND
    if(strcmp(arg1, "static_command") == 0) {
        DEBUG_PRINT("Statically retrieving data from array command[] in included file...\n");
        *data_size = sizeof(command) - 1;	
        return command;
    }
    #endif

    // Return NULL if arg1 is unrecognized string or defines are not set correctly
    DEBUG_PRINT("Static retrieval from file failed; argument arg1 of function static_from_file not recognized and/or defines not correctly set in included headers?\n");
    return NULL;
}
