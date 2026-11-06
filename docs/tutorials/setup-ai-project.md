# How to set up an AI project

AI rooms in ONLYOFFICE Apps give your team an AI assistant that knows how you work and what your documents say. They come in three types that work together:

- An **instructions room** holds skills: short Markdown files that tell the assistant how to do a task, such as writing in your brand voice.
- A **knowledge room** holds documents that ONLYOFFICE Apps vectorizes, so the assistant can find answers in them.
- An **AI project** links instructions and knowledge rooms, sets the model the assistant chats with, and is shared with the team. Project members can use the linked rooms without being invited to each of them.

This guide shows you how to set up an AI project from scratch using the MCP server.

## Scenario

Imagine you lead the support team at Meridian Corp. Your agents answer customer questions about the product and must write in the company's tone. You want them to have an assistant that follows the support style guide and answers from the product documentation.

## What you'll learn

- [Check that AI is available on your portal](#step-1-check-that-ai-is-available)
- [Create an instructions room and add skills to it](#step-2-create-an-instructions-room-with-skills)
- [Create a knowledge room and fill it with documents](#step-3-create-a-knowledge-room-with-documents)
- [Create an AI project, link the rooms and choose a model](#step-4-create-the-ai-project)
- [Share the project with your team](#step-6-share-the-project-with-your-team)

This tutorial uses the `get_ai_config`, `create_ai_room`, `upload_file`, `get_ai_skills`, `copy_batch_items`, `get_folder_content`, `retry_vectorization`, `link_ai_project_sources`, `get_ai_project_sources`, `get_ai_profiles`, `set_ai_project_model`, `get_room_access_levels`, `set_room_security` and `delete_ai_room` tools.

## Before you proceed

- Make sure you [connect your ONLYOFFICE Apps MCP server to your MCP client of choice](../getting-started/clients.md).
- AI rooms require ONLYOFFICE Apps 4.1 or later with AI enabled on the portal. Knowledge rooms also require vectorization to be enabled. Both are set up by the portal administrator.
- The `ai_rooms` toolset must be enabled. It is enabled by default; if your configuration lists toolsets in `DOCSPACE_TOOLSETS`, add `ai_rooms` to the list.

> **Note:** AI rooms are listed in their own **AI rooms** section, not in the **Rooms** section. Tools such as `get_rooms_folder` do not show them; the AI uses `get_ai_rooms_folder` instead.

### Step 1: Check that AI is available

**Enter this prompt into your MCP client:**

```text
Is AI enabled on my ONLYOFFICE Apps portal, and can I create knowledge rooms?
```

The AI calls `get_ai_config` and reports two flags: whether AI is ready and whether vectorization is enabled. If AI is not ready, the other AI room tools are refused; ask the portal administrator to set up AI before continuing.

### Step 2: Create an instructions room with skills

A skill is a Markdown file that starts with a short header, the frontmatter, giving its name and a description of when to use it. The assistant reads the description to decide when the skill applies.

**Try this prompt:**

```text
Create an instructions room called "Meridian Support — Skills". Add a skill named "support-tone" that tells the assistant to answer customers politely, in short paragraphs, without technical jargon, and to always end with an offer of further help.
```

The AI calls `create_ai_room` with the instructions room type, writes the skill and uploads it with `upload_file`. The file looks like this:

```markdown
---
name: support-tone
description: Writes customer support answers in the Meridian Corp tone.
---

Answer politely, in short paragraphs, without technical jargon.
Always end with an offer of further help.
```

**Verify the skill was picked up:**

```text
What skills are in the "Meridian Support — Skills" room?
```

This calls `get_ai_skills` and lists the name and description of each skill.

> **Note:**
>
> - An instructions room accepts only Markdown (`.md`) files, and each must start with the frontmatter. The skill name may contain only lowercase letters, digits and single hyphens, up to 64 characters; the description is up to 1024 characters. A room holds up to 100 skills.
> - If a file is refused, the AI receives the reason from the portal, such as a missing frontmatter, and can fix the file and upload it again.
> - To change a skill, ask the AI to rewrite it. The AI reads the skill with `download_file_as_text` and uploads the new text with `upload_file` under the same name with `overwrite` set, so the skill keeps its ID and the former text stays in the version history. Without `overwrite`, the upload adds a second skill.

### Step 3: Create a knowledge room with documents

**Try this prompt:**

```text
Create a knowledge room called "Meridian Support — Product Docs" and copy all documents from the "Product Documentation" folder of the "Meridian Corp — Website Redesign" room into it.
```

The AI calls `create_ai_room` with the knowledge room type, finds the documents with `get_folder_content` and copies them with `copy_batch_items`. You can also ask the AI to write a text or Markdown file, such as a list of frequently asked questions, and upload it with `upload_file`.

ONLYOFFICE Apps vectorizes every file added to a knowledge room. **Check the progress:**

```text
Has vectorization finished for the files in the "Meridian Support — Product Docs" room?
```

The AI calls `get_folder_content` and reads the `vectorizationStatus` of each file: `0` while the file is being vectorized, `1` when it is done and `2` when it failed. To try the failed files again:

```text
Retry the vectorization of the failed files in the "Meridian Support — Product Docs" room.
```

This calls `retry_vectorization`. Only room managers can retry vectorization.

> **Note:** A knowledge room accepts text, Markdown, JSON, CSV, Word, Excel, PowerPoint and PDF files up to 30 MB. The `upload_file` tool uploads only text and Markdown; other documents are copied or moved into the room.

### Step 4: Create the AI project

**Try this prompt:**

```text
Create an AI project called "Meridian Support Assistant" and link the "Meridian Support — Skills" and "Meridian Support — Product Docs" rooms to it.
```

The AI calls `create_ai_room` with the AI project type and then `link_ai_project_sources`. **Verify the links:**

```text
Which rooms are linked to the "Meridian Support Assistant" project?
```

This calls `get_ai_project_sources` and lists the linked instructions and knowledge rooms.

> **Note:**
>
> - An AI project holds no files of its own: everything the assistant uses comes from the linked rooms. A project links up to 20 instructions rooms and 20 knowledge rooms.
> - Linking a room gives every project member read access to it. To take it away, ask the AI to unlink the room; it calls `unlink_ai_project_sources`.

### Step 5: Choose the model

A new project uses the default model of the portal. To choose another one:

**Try this prompt:**

```text
Which models can the "Meridian Support Assistant" project use? Set it to one that can call tools.
```

The AI calls `get_ai_profiles`, which lists only the models suited for chat, and then `set_ai_project_model`. The model can be changed later, but the project cannot be switched back to the portal default.

### Step 6: Share the project with your team

**Try this prompt:**

```text
What access levels can I assign in the "Meridian Support Assistant" project?
```

The AI calls `get_room_access_levels`, which for an AI project returns two roles:

- **Member** — chats with the assistant and reads the linked rooms.
- **Project manager** — also changes the project, its linked rooms and its model, and invites new users.

**Invite the team:**

```text
Invite Alex Chen as a project manager and Priya Nair and Jordan Mills as members of the "Meridian Support Assistant" project.
```

The AI calls `get_all_people` to find the users and `set_room_security` to invite them.

Your team can now open the project in the **AI rooms** section of ONLYOFFICE Apps and chat with an assistant that follows the support tone and answers from the product documentation.

## Cleaning up

AI rooms cannot be archived. When a project is no longer needed, ask the AI to delete it:

```text
Delete the "Meridian Support Assistant" project.
```

The AI calls `delete_ai_room`. **The deletion is permanent:** the room and all its files are removed without going to the trash. Deleting a project does not delete the linked instructions and knowledge rooms; delete them separately if they are no longer needed. The `delete_ai_room` tool refuses rooms of other types, which are archived with `archive_room` instead.
