/**
 * (c) Copyright Ascensio System SIA 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @license
 */

/* eslint-disable no-underscore-dangle */

import * as z from "zod"

export const RoomTypeSchema = z.union([
	z.literal("FillingFormsRoom").describe("Form Filling Room. Upload PDF forms into the room. Invite members and guests to fill out a PDF form. Review completed forms and analyze data automatically collected in a spreadsheet."),
	z.literal("EditingRoom").describe("Collaboration room. Collaborate on one or multiple documents with your team."),
	z.literal("CustomRoom").describe("Custom room. Apply your own settings to use this room for any custom purpose."),
	z.literal("PublicRoom").describe("Public room. Share documents for viewing, editing, commenting, or reviewing without registration. You can also embed this room into any web interface."),
	z.literal("VirtualDataRoom").describe("Virtual Data Room. Use VDR for advanced file security and transparency. Set watermarks, automatically index and track all content, restrict downloading and copying."),
	z.literal(1).describe("The number representation of the FillingFormsRoom type."),
	z.literal(2).describe("The number representation of the EditingRoom type."),
	z.literal(5).describe("The number representation of the CustomRoom type."),
	z.literal(6).describe("The number representation of the PublicRoom type."),
	z.literal(8).describe("The number representation of the VirtualData Room type."),
])

export const RoomInvitationAccessSchema = z.union([
	z.literal("None").describe("None. No access to the room."),
	z.literal("Read").describe("Viewer. File viewing."),
	z.literal("Review").describe("Reviewer. Operations with existing files: viewing, reviewing, commenting."),
	z.literal("Comment").describe("Commenter. Operations with existing files: viewing, commenting."),
	z.literal("FillForms").describe("Form filler. Form fillers can fill out forms and view only their completed/started forms within the Complete and In Process folders."),
	z.literal("RoomManager").describe("Room manager (Paid). Room managers can manage the assigned rooms, invite new users and assign roles below their level."),
	z.literal("Editing").describe("Editor. Operations with existing files: viewing, editing, form filling, reviewing, commenting."),
	z.literal("ContentCreator").describe("Content creator. Content creators can create and edit files in the room, but can't manage users, or access settings."),
	z.literal(0).describe("The number representation of the None access level."),
	z.literal(2).describe("The number representation of the Read access level."),
	z.literal(5).describe("The number representation of the Review access level."),
	z.literal(6).describe("The number representation of the Comment access level."),
	z.literal(7).describe("The number representation of the FillForms access level."),
	z.literal(9).describe("The number representation of the RoomManager access level."),
	z.literal(10).describe("The number representation of the Editing access level."),
	z.literal(11).describe("The number representation of the ContentCreator access level."),
])

export const FormFillingRoomInvitationAccessSchema = z.union([
	RoomInvitationAccessSchema._def.options[4],
	RoomInvitationAccessSchema._def.options[5],
	RoomInvitationAccessSchema._def.options[7],
	RoomInvitationAccessSchema._def.options[12],
	RoomInvitationAccessSchema._def.options[13],
	RoomInvitationAccessSchema._def.options[15],
])

export const CollaborationRoomInvitationAccessSchema = z.union([
	RoomInvitationAccessSchema._def.options[1],
	RoomInvitationAccessSchema._def.options[5],
	RoomInvitationAccessSchema._def.options[6],
	RoomInvitationAccessSchema._def.options[7],
	RoomInvitationAccessSchema._def.options[9],
	RoomInvitationAccessSchema._def.options[13],
	RoomInvitationAccessSchema._def.options[14],
	RoomInvitationAccessSchema._def.options[15],
])

export const CustomRoomInvitationAccessSchema = z.union([
	RoomInvitationAccessSchema._def.options[1],
	RoomInvitationAccessSchema._def.options[2],
	RoomInvitationAccessSchema._def.options[3],
	RoomInvitationAccessSchema._def.options[5],
	RoomInvitationAccessSchema._def.options[6],
	RoomInvitationAccessSchema._def.options[7],
	RoomInvitationAccessSchema._def.options[9],
	RoomInvitationAccessSchema._def.options[10],
	RoomInvitationAccessSchema._def.options[11],
	RoomInvitationAccessSchema._def.options[13],
	RoomInvitationAccessSchema._def.options[14],
	RoomInvitationAccessSchema._def.options[15],
])

export const PublicRoomInvitationAccessSchema = z.union([
	RoomInvitationAccessSchema._def.options[5],
	RoomInvitationAccessSchema._def.options[7],
	RoomInvitationAccessSchema._def.options[13],
	RoomInvitationAccessSchema._def.options[15],
])

export const VirtualDataRoomInvitationAccessSchema = z.union([
	RoomInvitationAccessSchema._def.options[1],
	RoomInvitationAccessSchema._def.options[4],
	RoomInvitationAccessSchema._def.options[5],
	RoomInvitationAccessSchema._def.options[6],
	RoomInvitationAccessSchema._def.options[7],
	RoomInvitationAccessSchema._def.options[9],
	RoomInvitationAccessSchema._def.options[12],
	RoomInvitationAccessSchema._def.options[13],
	RoomInvitationAccessSchema._def.options[14],
	RoomInvitationAccessSchema._def.options[15],
])
