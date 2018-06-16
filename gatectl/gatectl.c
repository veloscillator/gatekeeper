/*++

Module Name:

	gatectl.c

Abstract:

	Application for interfacing with Gatekeeper filter driver. 

Environment:

	User mode

--*/

#include <DriverSpecs.h>
_Analysis_mode_(_Analysis_code_type_user_code_)

#include <stdlib.h>
#include <windows.h>
#include <fltUser.h>
#include <stdio.h>
#include <assert.h>
#include "gatekeeper.h"


void
usage(void)
{
	printf(
		"Usage: gatectl <action> <arg>\n"
		"       gatectl directory <directory>: Monitor provided directory (clearing previous)\n"
		"       gatectl clear: Clear all directory and revoke settings\n"
	    "       gatectl revoke <str>: Revoke access to files (within directory) matching this string\n"
	    "       gatectl unrevoke <str>: Remove previously created revoke rule\n"
	);
}

HRESULT
SendGatekeeperMessage(
	_In_ HANDLE gatekeeperPort,
	_In_ GATEKEEPER_CMD command,
	_In_opt_ const char* argument
)
/*++

Routine Description:

	Sends specified message to gatekeeper driver (with optional string argument).

Arguments:

	gatekeeperPort - (Open) communication port with driver.
	command - Command.
	argument - Optional string sent along as part of message.

Return Value:

	HRESULT.

--*/
{
	GATEKEEPER_MSG msg;

	msg.cmd = command;
	if (argument != NULL) {
		const size_t argumentSize = strlen(argument) + 1; // +1 for \0
		if (argumentSize > GATEKEEPER_MAX_PATH) {
			return E_BOUNDS;
		}
		memcpy_s(&msg.data, sizeof(msg) - offsetof(GATEKEEPER_MSG, data), argument, argumentSize);
	}

	DWORD bytesReturned;
	return FilterSendMessage(
		gatekeeperPort,
		&msg,
		(DWORD)sizeof(msg),
		NULL,
		0,
		&bytesReturned
	);
}

int _cdecl
main(
	_In_ int argc,
	_In_reads_(argc) char* argv[])
	/*++

	Routine Description:

		Entry point.

	--*/
{
	GATEKEEPER_CMD cmd;
	char* argument = NULL;


	//
	// Parse arguments.
	//
	
	if (argc < 2) {
		usage();
		return E_INVALIDARG;
	}

	if (strcmp(argv[1], "directory") == 0) {

		if (argc != 3) {
			usage();
			return E_INVALIDARG;
		}

		printf("Setting directory to '%s'...\n", argv[2]);

		cmd = GatekeeperCmdDirectory;
		argument = argv[2];

	}
	else if (strcmp(argv[1], "revoke") == 0) {

		if (argc != 3) {
			usage();
			return E_INVALIDARG;
		}

		printf("Creating revoke rule for '%s'...\n", argv[2]);

		cmd = GatekeeperCmdRevoke;
		argument = argv[2];

	}
	else if (strcmp(argv[1], "unrevoke") == 0) {

		if (argc != 3) {
			usage();
			return E_INVALIDARG;
		}

		printf("Removing revoke rule for '%s'...\n", argv[2]);

		cmd = GatekeeperCmdUnrevoke;
		argument = argv[2];

	}
	else if (strcmp(argv[1], "clear") == 0) {

		if (argc != 2) {
			usage();
			return E_INVALIDARG;
		}

		printf("Clearing directory and all revoke rules...\n");

		cmd = GatekeeperCmdClear;

	}
	else {
		usage();
		return E_INVALIDARG;
	}
	
	
	//
	// Establish connectino with gatekeeper driver.
	//

	HANDLE gatekeeperPort;
	HRESULT hr = FilterConnectCommunicationPort(
		GATEKEEPER_PORT,
		0,
		NULL,
		0,
		NULL,
		&gatekeeperPort);
	if (FAILED(hr)) {
		// TODO Message.
		return hr;
	}


	//
	// Send message to driver and process response.
	//

	// TODO Any special handling of directory/clear calls.

	hr = SendGatekeeperMessage(gatekeeperPort, cmd , argument);

	if (SUCCEEDED(hr)) {
		printf("Operation succeeded\n");
	} else {
		// TODO More detail.
		printf("Operation failed\n");
	}
	
	CloseHandle(gatekeeperPort);

	return hr;
}