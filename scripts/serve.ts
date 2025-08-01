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

import {spawn} from "node:child_process"
import {load} from "./env.ts"

load()

const args: string[] = ["node"]

if (process.env.HTTP_PROXY !== undefined) {
	args.push("--require", "./util/proxy.ts")
}

args.push("app/main.ts")

spawn("pnpm", args, {
	env: process.env,
	stdio: "inherit",
	shell: true,
})
