/*++

Copyright (c) 1989-2002  Microsoft Corporation

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

// Defines the max size a path can be.
// TODO Remove limitation.
#define GATEKEEPER_MAX_PATH 1024

typedef enum {

	GatekeeperCmdDirectory,
	GatekeeperCmdClear,
	GatekeeperCmdRevoke,
	GatekeeperCmdUnrevoke

} GATEKEEPER_CMD;

typedef struct {

	GATEKEEPER_CMD cmd;
	unsigned char data[GATEKEEPER_MAX_PATH];

} GATEKEEPER_MSG, *PGATEKEEPER_MSG;



#endif // __GATEKEEPER_H__