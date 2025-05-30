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

import type {Result} from "../../util/result.ts"
import {error, ok} from "../../util/result.ts"
import type {Client} from "../client.ts"
import type {Response} from "./internal/response.ts"

export class SettingsService {
	private c: Client

	constructor(s: Client) {
		this.c = s
	}

	//
	// SettingsController
	//

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/web/ASC.Web.Api/Api/Settings/SettingsController.cs/#L476 | DocSpace Reference}
	 */
	async getSupportedCultures(s: AbortSignal): Promise<Result<[unknown, Response], Error>> {
		let u = this.c.createUrl("api/2.0/settings/cultures")
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "GET", u.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.fetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		return ok(f.v)
	}

	/**
	 * {@link https://github.com/ONLYOFFICE/DocSpace-server/blob/v3.0.4-server/web/ASC.Web.Api/Api/Settings/SettingsController.cs/#L492 | DocSpace Reference}
	 */
	async getTimeZones(s: AbortSignal): Promise<Result<[unknown, Response], Error>> {
		let u = this.c.createUrl("api/2.0/settings/timezones")
		if (u.err) {
			return error(new Error("Creating URL.", {cause: u.err}))
		}

		let req = this.c.createRequest(s, "GET", u.v)
		if (req.err) {
			return error(new Error("Creating request.", {cause: req.err}))
		}

		let f = await this.c.fetch(req.v)
		if (f.err) {
			return error(new Error("Fetching request.", {cause: f.err}))
		}

		return ok(f.v)
	}
}
