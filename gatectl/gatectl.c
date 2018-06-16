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

int _cdecl
main(
	_In_ int argc,
	_In_reads_(argc) char* argv[])
	/*++

	Routine Description:

		Entry point.

	--*/
{
	HRESULT hr;
	HANDLE gatekeeperPort = INVALID_HANDLE_VALUE;


	//
	// Establish connectino with gatekeeper driver.
	//

	
	hr = FilterConnectCommunicationPort(
		GATEKEEPER_PORT,
		0,
		NULL,
		0,
		NULL,
		&gatekeeperPort);
	if (FAILED(hr)) {
		return hr;
	}


	//
	// Parse arguments and issue command.
	//

	if (argc < 2) {
		usage();
		return E_INVALIDARG;
	}

	if (strcmp(argv[1], "directory") == 0) {

		if (argc != 3) {
			usage();
			hr = E_INVALIDARG;
			goto cleanup;
		}

		printf("Setting directory to '%s'...\n", argv[2]);

		// TODO

	} else if (strcmp(argv[1], "revoke") == 0) {

		if (argc != 3) {
			usage();
			hr = E_INVALIDARG;
			goto cleanup;
		}

		printf("Creating revoke rule for '%s'...\n", argv[2]);

		// TODO

	} else if (strcmp(argv[1], "unrevoke") == 0) {
		
		if (argc != 3) {
			usage();
			hr = E_INVALIDARG;
			goto cleanup;
		}

		printf("Removing revoke rule for '%s'...\n", argv[2]);

		// TODO

	} else if (strcmp(argv[1], "clear") == 0) {

		if (argc != 2) {
			usage();
			hr = E_INVALIDARG;
			goto cleanup;
		}
		
		printf("Clearing directory and all revoke rules...\n");

		// TODO

	} else {
		usage();
		hr = E_INVALIDARG;
		goto cleanup;
	}





	
cleanup:

	if (gatekeeperPort != INVALID_HANDLE_VALUE) {
		CloseHandle(gatekeeperPort);
	}

	return hr;
}