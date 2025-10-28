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

import {ProxyAgent, setGlobalDispatcher} from "undici"

if (process.env.HTTP_PROXY === undefined) {
	throw new Error("HTTP_PROXY environment variable is not set")
}

if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === undefined) {
	process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"
}

setGlobalDispatcher(new ProxyAgent(process.env.HTTP_PROXY))

// https://github.com/gajus/global-agent/issues/52/#issuecomment-1134525621
// https://docs.proxyman.com/debug-devices/nodejs/#id-1.-node-fetch
