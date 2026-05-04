# How to effectively manage your project documentation throughout its lifecycle

Creating content requires numerous reviews and iterations from editors and other team members before a final draft, and without proper management to keep track of these files and versions, it can get confusing. The DocSpace MCP server facilitates this process, improving efficiency throughout the process.

## Scenario

Imagine you're part of a content team creating marketing copies for a new campaign. This content passes through different stages — rough draft, reviews by multiple stakeholders before being greenlit for publishing, and subsequent archival.
This tutorial walks you through managing the entire document lifecycle, from first draft to cleanup.

## What you'll learn

- [How to upload documents and verify their location](#step-1-upload-your-first-draft)
- [How to have the AI read and reason about a document's contents](#step-3-review-the-document-with-your-mcp-client)
- [How to update a file with a revised version](#step-4-upload-a-revised-version)
- [How to compare the two drafts](#step-5-compare-the-two-drafts)
- [How to clean up superseded drafts](#step-7-clean-up-old-drafts)

**Tools used:** `upload_file`, `get_file_info`, `download_file_as_text`, `update_file`, `move_batch_items`, `copy_batch_items`, `delete_file`, `get_folder_content`

## Before you proceed

- Make sure you [connect your DocSpace MCP server to your MCP client of choice](../getting-started/clients.md).

> **Note:** Every AI MCP client sends a confirmation message to deny or confirm every action after you issue a prompt. This confirmation message differs from client to client — Le Chat uses `Always allow`, `Decline` or `Continue`.

### Step 1: Upload your first draft

You have the first draft of the product marketing copy. You'll upload it to the `03 — Drafts & Work in Progress` folder inside your project room.

**Try this prompt:**

```text
Upload the file "launch-brief-v1.docx" to the "03 — Drafts & Work in Progress" folder in the "Meridian Corp — Website Redesign" room.
```

**For developers:** The `upload_file` tool accepts a file path and a destination folder ID. When the user specifies a folder by name, the AI first calls `get_folder_content` on the room to resolve the folder name to its ID, then calls `upload_file` with that ID as the destination.

Once uploaded, verify it landed in the right place:

```text
Show me the contents of the "03 — Drafts & Work in Progress" folder.
```

### Step 2: Retrieve file metadata

Confirm the file's details — its ID, creation timestamp, file size, and type.

**Try this prompt:**

```text
Get the file information for "launch-brief-v1.docx".
```

The AI calls `get_file_info` and returns the file's metadata. This is particularly useful when you need to reference a specific file version or confirm who created it.

**Note the file's ID** — it will be used in subsequent operations.

### Step 3: Review the document with your MCP client

One of the most powerful capabilities of the DocSpace MCP server is allowing an AI agent to actually read the contents of a document for analysis, summarization, or review.

**Try this prompt:**

```text
Download and read the contents of "launch-brief-v1.docx". Summarize the key sections and note any ideas for improvement.
```

The AI calls `download_file_as_text`, retrieves the document text, and reasons about it directly. It might respond with something like:

> "The brief covers the project overview, target audience, and key messaging pillars. However, the 'Success Metrics' section appears to be a placeholder with no content, and the 'Timeline' section is missing entirely."

This workflow is powerful for asynchronous document review — instead of reading the whole document yourself, you can ask the AI to surface gaps and issues.

**For developers:** `download_file_as_text` returns plain text. It works best on text-based formats (DOCX, TXT, MD). For files with complex formatting, some structure may be lost in the text conversion — your agent should handle this gracefully.

### Step 4: Upload a revised version

After incorporating feedback, you have a second draft ready. Upload it alongside the first.

**Try this prompt:**

```text
Upload "launch-brief-v2.docx" to the "03 — Drafts & Work in Progress" folder.
```

Alternatively, if you want to update the existing file record rather than add a new one:

```text
Update the file "launch-brief-v1.docx" with the revised version "launch-brief-v2.docx".
```

This uses `update_file` to replace the file content while preserving the same file record and ID.

**When to use `upload_file` vs `update_file`:**
- Use `upload_file` when you want to keep both versions side by side (version comparison)
- Use `update_file` when you want a clean replacement and don't need to preserve the old version

### Step 5: Compare the two drafts

With both versions available, compare them:

```text
Download and compare "launch-brief-v1.docx" and "launch-brief-v2.docx". What changed between the two versions?
```

The AI will call `download_file_as_text` twice and then produce a diff summary. This is a lightweight alternative to tracked changes for teams who don't use collaborative editing features.

### Step 6: Promote the approved document

The brief has been approved by the client. Move it from the Drafts folder to the Final Deliverables folder.

**Try this prompt:**

```text
Move "launch-brief-v2.docx" from "03 — Drafts & Work in Progress" to "04 — Final Deliverables" in the "Meridian Corp — Website Redesign" room.
```

The AI calls `move_batch_items` with the file ID and destination folder ID.

**If you want to keep a copy in Drafts** as a reference:

```text
Copy "launch-brief-v2.docx" from "03 — Drafts & Work in Progress" to "04 — Final Deliverables".
```

This uses `copy_batch_items` instead, which leaves the original in place.

**Key distinction:**
- `move_batch_items` — removes from source, places in destination
- `copy_batch_items` — original stays in source, a copy is placed in destination

### Step 7: Clean up old drafts

Now that the approved version is in Final Deliverables, delete the first draft to keep things tidy.

**Try this prompt:**

```text
Delete "launch-brief-v1.docx" from the "03 — Drafts & Work in Progress" folder.
```

The AI calls `delete_file`. Before proceeding, the AI might ask you to confirm since deletion is irreversible. Always confirm you have the right file before saying yes.

**Final verification:**

```text
Show me the contents of both the "03 — Drafts & Work in Progress" and "04 — Final Deliverables" folders.
```

You should see only `launch-brief-v2.docx` in Final Deliverables and an empty (or cleaned-up) Drafts folder.
