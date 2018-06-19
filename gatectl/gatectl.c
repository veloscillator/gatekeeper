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
#include <strsafe.h>
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
	_In_opt_ const wchar_t* argument
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
		const size_t argumentSize = (wcslen(argument) + 1) * sizeof(argument[0]);
		if (argumentSize > GATEKEEPER_MAX_BYTES) {
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
wmain(
	_In_ int argc,
	_In_reads_(argc) wchar_t* argv[])
	/*++

	Routine Description:

		Entry point.

	--*/
{
	HRESULT hr;
	GATEKEEPER_CMD cmd;
	const wchar_t* argument = NULL;
	WCHAR scratch[GATEKEEPER_MAX_BYTES]; // Temporary scratch space.


	//
	// Parse arguments.
	//
	
	if (argc < 2) {
		usage();
		return E_INVALIDARG;
	}

	if (wcscmp(argv[1], L"directory") == 0) {

		WCHAR scratch2[GATEKEEPER_MAX_BYTES]; // Need more scratch space for path conversion.
		DWORD len;

		if (argc != 3) {
			usage();
			return E_INVALIDARG;
		}

		printf("Setting directory to '%ls'...\n", argv[2]);

		//
		// Convert path to weird format needed by driver.
		//

		len = GetFullPathNameW(argv[2], sizeof(scratch2) / sizeof(TCHAR), scratch2, NULL);
		if (len == 0) {
			// TODO Get error code.
			return E_FAIL;
		} else if (len > sizeof(scratch2) / sizeof(TCHAR)) {
			return E_BOUNDS;
		}

		hr = StringCchPrintf(scratch, sizeof(scratch) / sizeof(scratch[0]), L"\\??\\%s", scratch2);
		if (FAILED(hr)) {
			return hr;
		}

		printf("full path '%ls' weird path '%ls'\n", scratch2, scratch);

		cmd = GatekeeperCmdDirectory;
		argument = scratch;

	}
	else if (wcscmp(argv[1], L"revoke") == 0) {

		if (argc != 3) {
			usage();
			return E_INVALIDARG;
		}

		printf("Creating revoke rule for '%ls'...\n", argv[2]);

		cmd = GatekeeperCmdRevoke;
		argument = argv[2];

	}
	else if (wcscmp(argv[1], L"unrevoke") == 0) {

		if (argc != 3) {
			usage();
			return E_INVALIDARG;
		}

		printf("Removing revoke rule for '%ls'...\n", argv[2]);

		cmd = GatekeeperCmdUnrevoke;
		argument = argv[2];

	}
	else if (wcscmp(argv[1], L"clear") == 0) {

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
	hr = FilterConnectCommunicationPort(
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