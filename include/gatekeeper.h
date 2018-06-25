/*++

Module Name:

	gatekeeper.h

Abstract:

	Header shared between Gatekeeper.sys and gatectl.exe.

Environment:

	Kernel and user mode

--*/

#ifndef __GATEKEEPER_H__
#define __GATEKEEPER_H__


#define GATEKEEPER_PORT L"\\Gatekeeper"

// Defines the max size of GATEKEEPER_MSG data field.
// TODO Remove limitation.
#define GATEKEEPER_MAX_BYTES 1024
#define GATEKEEPER_MAX_WCHARS (GATEKEEPER_MAX_BYTES / sizeof(WCHAR))

typedef enum {

	GatekeeperCmdDirectory,
	GatekeeperCmdClear,
	GatekeeperCmdRevoke,
	GatekeeperCmdUnrevoke,
	GatekeeperCmdLogFile,

} GATEKEEPER_CMD;

typedef struct {

	GATEKEEPER_CMD cmd;
	unsigned short data[GATEKEEPER_MAX_BYTES];

} GATEKEEPER_MSG, *PGATEKEEPER_MSG;



#endif // __GATEKEEPER_H__