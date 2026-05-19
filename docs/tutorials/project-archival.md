# How to archive projects and offboard team members after project completion

After project completion, practicing archiving and offboarding ensures that the project data remains searchable and secure for any future use. It also:

- ensures proper transition of knowledge and responsibilities as a team member or group leaves
- preserves company knowledge and frees up space and tools for other projects.
- ensures compliance and aids auditing, as proper transition management ensures files are readily available

This guide will teach you how the connection created by the ONLYOFFICE DocSpace MCP server with AI clients enables you to properly archive your completed projects with simple human prompts.

## Scenario

With the Meridian Corp website redesign project officially complete and signed off by the client, with all deliverables properly handled, it's now time to properly close out the project room. This process will remove contractor access, clean up temporary working files, do a final audit, and archive the room so it's preserved for reference but no longer clutters the active workspace.

## What you'll learn

- [How to conduct a proper access audit before closing a room](#step-1-conduct-a-full-access-audit)
- [How to revoke access for contractors and guests safely](#step-2-remove-external-access)
- [How to clean up working/temp content while preserving final deliverables](#step-3-audit-the-room-contents)
- [How to do a final pre-archive verification](#step-6-final-pre-archive-verification)
- [How to archive a room correctly](#step-7-archive-the-room)

**Tools used:** `get_room_security_info`, `set_room_security`, `get_folder_content`, `get_file_info`, `delete_file`, `delete_folder`, `archive_room`, `download_file_as_text`

## Before you proceed

- Make sure you [connect your DocSpace MCP server to your MCP client of choice](../getting-started/clients.md).

### Step 1: Conduct a full access audit

Before deleting or changing anything, it's important to get a complete picture of who still has access to the room.

**Try this prompt:**

```text
Show me everyone who currently has access to the "Meridian Corp — Website Redesign" room, including their roles and email addresses if available.
```

The AI calls `get_room_security_info` and returns the full member list. Review it carefully and categorize each person into `keep` and `remove` groups:

- **Team members moving to other projects** (remove now — no longer working on this project)
- **Client stakeholders / external reviewers** (remove now — project is over)
- **Room admins** (keep until final archive step)

For this scenario, you find:
- **Sam Rivera** (Developer) — **remove** (reassigned to another project)
- **Yuki Tanaka** (Content Writer) — **remove** (reassigned to another project)
- **Aisha Okafor** (Content Writer) — **remove** (reassigned to another project)
- **Marcus Webb** (Client Success Manager) — **keep for now**

### Step 2: Remove external access

Revoke access for all external parties.

**Try this prompt:**

```text
Remove Sam Rivera, Yuki Tanaka, and Aisha Okafor from the "Meridian Corp — Website Redesign" room as they've been reassigned to other projects. Marcus Webb still needs access during the archival process.
```

The AI calls `set_room_security` with removal instructions for the specified users.

**Verify access was revoked:**

```text
Show me the updated access list for "Meridian Corp — Website Redesign".
```

Confirm that the reassigned team members no longer have access. This is a critical security step — team members should not retain access to rooms for projects they are no longer working on.

### Step 3: Audit the room contents

Now inspect the contents of the room to decide what stays and what should be deleted before archiving.

**Try this prompt:**

```text
Show me the complete contents of all folders in the "Meridian Corp — Website Redesign" room.
```

This calls `get_folder_content` on the room and its subfolders. Your results will look like this:

- `01 — Briefs & Requirements` — **keep** (project history)
- `02 — Design Assets` — **keep** (final assets)
- `03 — Drafts & Work in Progress` — **clean up** (old drafts no longer needed)
- `04 — Final Deliverables` — **keep** (approved outputs)

### Step 4: Identify files for deletion

Inspect the Drafts folder to confirm what can safely be deleted.

**Try this prompt:**

```text
List all files in the "03 — Drafts & Work in Progress" folder with their details.
```

For each file, check the details (creation date, last modified, file name) to confirm it's genuinely a working draft that's not relevant or has been replaced by a more complete one.

**Try this prompt for any file to confirm relevance:**

```text
Download and read the contents of "old-brief-draft.docx". Is there anything in it not covered by the final version in the deliverables folder?
```

The AI calls `download_file_as_text` and compares content — useful for ensuring you're not deleting anything unique before you delete it.

### Step 5: Clean up the drafts folder

Once you're confident about what to delete:

**Try this prompt:**

```text
Delete all files in the "03 — Drafts & Work in Progress" folder.
```

If you want to be more selective:

```text
Delete "old-brief-draft.docx" and "wireframe-sketch-v1.png" from the "03 — Drafts & Work in Progress" folder.
```

After deleting the files, you can also remove the now-empty folder:

```text
Delete the "03 — Drafts & Work in Progress" folder.
```

The AI calls `delete_folder`.
**Note:** DocSpace will prevent deletion of a folder that still contains files, so you must empty it first.

### Step 6: Final pre-archive verification

Before archiving, perform a final check to confirm the room is in the state you want to preserve.

**Try this prompt:**

```text
Give me a final summary of the "Meridian Corp — Website Redesign" room — who has access, what folders exist, and what's in each folder.
```

The AI calls `get_room_security_info` and `get_folder_content` and produces a final state report. Confirm:

- Only internal team members remain in the access list
- Working files have been removed
- Final deliverables are intact
- The room structure is clean

### Step 7: Archive the room

Now close the room from active use.

**Try this prompt:**

```text
Archive the "Meridian Corp — Website Redesign" room.
```

The AI calls `archive_room`. The room will move to the archived section of DocSpace, meaning:

- It's no longer visible in the active rooms list
- No new files can be added to it
- Existing members can still view its contents for reference (read-only)
- It can be unarchived in the future if needed

**Important distinction:** Archiving is not the same as deleting. The room and all its contents are preserved — they're just moved out of the active workspace. This is the recommended default for completed projects.
