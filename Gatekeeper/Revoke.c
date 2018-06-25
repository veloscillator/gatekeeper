/*++

Module Name:

	Revoke.c

Abstract:

	Maintain and apply list of revoke rules.

Environment:

	Kernel mode

--*/


#include "Revoke.h"
#include <ntstrsafe.h>


#define GATEKEEPER_TAG 'gtKP' // Tag memory allocations to detect leaks.


void
RevokeListInit(
	_In_ PREVOKE_LIST RevokeList
)
/*++

Routine Description:

	Initializes new REVOKE_LIST.

Arguments:

	RevokeList - Uninitialized REVOKE_LIST structure.

Return Value:

	None.

--*/
{
	ExInitializeNPagedLookasideList(
		&RevokeList->FreeBuffers,
		NULL,
		NULL,
		POOL_NX_ALLOCATION,
		sizeof(REVOKE_RULE),
		GATEKEEPER_TAG,
		0);
	InitializeListHead(&RevokeList->Rules);
	FltInitializePushLock(&RevokeList->Lock);
}

void
RevokeListDestroy(
	_In_ PREVOKE_LIST RevokeList
)
/*++

Routine Description:

	Free resources taken by revoke list.

Arguments:

	RevokeList - List to destroy. No longer usable after return.

Return Value:

	None.

--*/
{
	RevokeListClear(RevokeList);
	ExDeleteNPagedLookasideList(&RevokeList->FreeBuffers); // GatekeeperClear freed all nodes.
	FltDeletePushLock(&RevokeList->Lock);
}

void
RevokeListClear(
	_In_ PREVOKE_LIST RevokeList
)
/*++

Routine Description:

	Clears all revoke rules.

Arguments:

	RevokeList - List of rules to clear.

Return Value:

	None.

--*/
{
	PLIST_ENTRY pList;
	PREVOKE_RULE rule;

	FltAcquirePushLockExclusive(&RevokeList->Lock);

	while (!IsListEmpty(&RevokeList->Rules)) {

		pList = RemoveHeadList(&RevokeList->Rules);

		rule = CONTAINING_RECORD(pList, REVOKE_RULE, ListBlock);
		ExFreeToNPagedLookasideList(&RevokeList->FreeBuffers, rule); // TODO Don't hold lock around free.

	}

	FltReleasePushLock(&RevokeList->Lock);
}

NTSTATUS
RevokeListAddRule(
	_In_ PREVOKE_LIST RevokeList,
	_In_ PCUNICODE_STRING Rule
)
/*++

Routine Description:

	Add a new rule to revoke list. Does not handle duplicates.

Arguments:

	RevokeList - List of rules to add to.

	Rule - New rule.

Return Value:

	NTSTATUS.

--*/
{
	NTSTATUS status;
	PREVOKE_RULE newRule = NULL;


	//
	// Create REVOKE_RULE structure.
	//

	newRule = ExAllocateFromNPagedLookasideList(&RevokeList->FreeBuffers);
	if (newRule == NULL) {
		return STATUS_NO_MEMORY;
	}

	// TODO RevokeRuleBuffer -> RuleBuffer.
	FLT_ASSERT(Rule->Length < sizeof(newRule->RuleBufferDoNotUse)); // Required of caller.

	// Copy Rule into newRule->Rule.
	newRule->Rule.Buffer = newRule->RuleBufferDoNotUse;
	newRule->Rule.MaximumLength = sizeof(newRule->RuleBufferDoNotUse);
	newRule->Rule.Length = Rule->Length;
	status = RtlStringCchCopyW(
		newRule->Rule.Buffer,
		newRule->Rule.MaximumLength / sizeof(newRule->Rule.Buffer[0]), // Length in WCHARS.
		Rule->Buffer);
	FLT_ASSERT(NT_SUCCESS(status)); // Due to caller validation.
	FLT_ASSERT(NT_SUCCESS(RtlUnicodeStringValidate(&newRule->Rule)));


	//
	// Insert into RevokeList.
	//

	FltAcquirePushLockExclusive(&RevokeList->Lock);
	InsertHeadList(&RevokeList->Rules, &newRule->ListBlock);
	FltReleasePushLock(&RevokeList->Lock);

	return STATUS_SUCCESS;
}

NTSTATUS
RevokeListRemoveRule(
	_In_ PREVOKE_LIST RevokeList,
	_In_ PCUNICODE_STRING Rule
)
/*++

Routine Description:

	Remove rule from revoke list. Does not handle duplicates.

Arguments:

	RevokeList - List of revoke rules to remove from.

	Rule - Rule to remove.

Return Value:

	STATUS_NOT_FOUND if no such rule. STATUS_SUCCESS if rule successfully removed.

--*/
{
	NTSTATUS status;

	FltAcquirePushLockExclusive(&RevokeList->Lock);

	PLIST_ENTRY head = &RevokeList->Rules;
	PLIST_ENTRY prev = &RevokeList->Rules;
	PLIST_ENTRY current = prev->Flink;

	status = STATUS_NOT_FOUND;
	while (current != head) {

		PREVOKE_RULE currentRule = CONTAINING_RECORD(current, REVOKE_RULE, ListBlock);

		if (RtlEqualUnicodeString(Rule, &currentRule->Rule, FALSE)) {
			// Remove from list.
			prev->Flink = current->Flink;
			current->Flink->Blink = prev;
			status = STATUS_SUCCESS;
			break;
		}

		prev = current;
		current = prev->Flink;
	}

	FltReleasePushLock(&RevokeList->Lock);
	return status;
}

BOOLEAN
RevokeListApplyRule(
	_In_ PCUNICODE_STRING Path,
	_In_ const PREVOKE_RULE Rule
)
/*++

Routine Description:

	Tries to match revoke rule to path by checking if rule is a substring of path.
	Case insensitive.

Arguments:

	Path - Path to apply rule to.

	Rule - Rule that defines match.

Return Value:

	TRUE if match found. FALSE otherwise.

--*/
{
	size_t charIndex;

	// Get length in characters.
	const size_t pathLen = Path->Length / sizeof(WCHAR);
	const size_t ruleLen = Rule->Rule.Length / sizeof(WCHAR);

	for (charIndex = 0; charIndex + ruleLen <= pathLen; charIndex++) {
		if (_wcsnicmp(&Path->Buffer[charIndex], Rule->Rule.Buffer, ruleLen) == 0) {
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN
RevokeListApplyRules(
	_In_ PREVOKE_LIST RevokeList,
	_In_ PCUNICODE_STRING Path
)
/*++

Routine Description:

	Determines whether a particular path matches revoke rules.

Arguments:

	RevokeList - Describes rules to apply.

	Path - Path to apply rules to.

Return Value:

	TRUE if Path has matched one or more rules. FALSE otherwise.

--*/
{
	FltAcquirePushLockShared(&RevokeList->Lock);

	BOOLEAN matched = FALSE;
	PLIST_ENTRY head = &RevokeList->Rules;
	PLIST_ENTRY prev = &RevokeList->Rules;
	PLIST_ENTRY current = prev->Flink;

	while (current != head) {

		PREVOKE_RULE rule = CONTAINING_RECORD(current, REVOKE_RULE, ListBlock);

		if (RevokeListApplyRule(Path, rule)) {
			matched = TRUE;
			break;
		}

		prev = current;
		current = prev->Flink;
	}

	FltReleasePushLock(&RevokeList->Lock);
	return matched;
}
