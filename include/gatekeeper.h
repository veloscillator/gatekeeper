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

typedef enum {

	GatekeeperCmdDirectory,
	GatekeeperCmdClear,
	GatekeeperCmdRevoke,
	GatekeeperCmdUnrevoke

} GATEKEEPER_CMD;


#pragma warning(push)
#pragma warning(disable:4200) // disable warnings for structures with zero length arrays.

typedef struct {

	GATEKEEPER_CMD cmd;
	unsigned char data[];

} GATEKEEPER_MSG, *PGATEKEEPER_MSG;

#pragma warning(pop)




#endif // __GATEKEEPER_H__