/*++

Module Name:

	Revoke.h

Abstract:

	Maintain and apply list of revoke rules.

Environment:

	Kernel mode.

--*/


#ifndef __REVOKE_H__
#define __REVOKE_H__


#include "gatekeeper.h"
#include <fltKernel.h>


typedef struct {

	//
	// Represents single revoke rule (currently implemented as simple string-matching).
	// Note in linked list.
	//

	LIST_ENTRY ListBlock;

	UNICODE_STRING Rule;
	WCHAR RuleBufferDoNotUse[GATEKEEPER_MAX_WCHARS]; // Don't access directly. Managed by Rule.

} REVOKE_RULE, *PREVOKE_RULE;

typedef struct {

	//
	// Linked list of revoke rules with reader/writer lock.
	//

	LIST_ENTRY Rules;
	NPAGED_LOOKASIDE_LIST FreeBuffers;
	EX_PUSH_LOCK Lock;

} REVOKE_LIST, *PREVOKE_LIST;


void
RevokeListInit(
	_In_ PREVOKE_LIST RevokeList
);

void
RevokeListDestroy(
	_In_ PREVOKE_LIST RevokeList
);

void
RevokeListClear(
	_In_ PREVOKE_LIST RevokeList
);

NTSTATUS
RevokeListAddRule(
	_In_ PREVOKE_LIST RevokeList,
	_In_ PCUNICODE_STRING Rule
);

NTSTATUS
RevokeListRemoveRule(
	_In_ PREVOKE_LIST RevokeList,
	_In_ PCUNICODE_STRING Rule
);

BOOLEAN
RevokeListApplyRules(
	_In_ PREVOKE_LIST RevokeList,
	_In_ PCUNICODE_STRING Path
);


#endif // __REVOKE_H__