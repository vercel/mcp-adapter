# @vercel/mcp-adapter

## 0.11.2

### Patch Changes

- c5c4ba5: chore: correctly resolve esm types

## 0.11.1

### Patch Changes

- fc2a6d8: Update README during NPM outage

## 0.11.0

### Minor Changes

- 7149159: Support adding serverMetadata to name and version the mcp server

## 0.10.0

### Minor Changes

- 71c14ea: Fix import error with mcp sdk

### Patch Changes

- 71c14ea: Fix module resolution

## 0.9.1

### Patch Changes

- c86da9a: Not optional

## 0.9.0

### Minor Changes

- 58efcf0: Add peerDependenciesMeta to fix not packaging the MCP SDK anymore

## 0.8.2

### Patch Changes

- 15fded0: Fix mjs module resolution

## 0.8.1

### Patch Changes

- 83e6fc7: Move zod to DevDep
- 12b61fd: Add more robust error handling to auth logic
- a522ffd: Move zod to devDep

## 0.8.0

### Minor Changes

- 166e5ab: Add option to disable SSE as per MCP spec

### Patch Changes

- 62518f2: Fix timeout scoping bug causing ReferenceError in SSE Handler
- c55c609: Update auth logic to not throw error is missing bearerToken

## 0.7.3

### Patch Changes

- 8fd2538: Fix missing non async argument

## 0.7.2

### Patch Changes

- 47eff5a: Fix allowing both async and non async handlers

## 0.7.1

### Patch Changes

- 13bd4fa: Add in auth handler

## 0.7.0

### Minor Changes

- b24064f: Update pinned mcp sdk version to 1.12.0

## 0.6.2

### Patch Changes

- 4f7a593: Fix SSE initializeServer

## 0.6.1

### Patch Changes

- b46856a: Allow an async initializeServer call

## 0.6.0

### Minor Changes

- 74d8a2c: Fix backwards compatibility algorithm with HTTP + SSE

## 0.5.1

### Patch Changes

- f48b5d6: Fix HTTP status code for some errors

## 0.5.0

### Minor Changes

- 24ce36e: added cli support to auto add the mcp route to a nextjs project

### Patch Changes

- 24ce36e: updated readme
- 48d4d64: fix out of date pnpm lock

## 0.4.1

### Patch Changes

- c0d7675: add logging

## 0.4.0

### Minor Changes

- 7fe14e6: make redis optional by only init on sse and messages

### Patch Changes

- 99d7837: fix release

## 0.2.4

### Patch Changes

- update readme with consistent docs ([#13309](https://github.com/vercel/vercel/pull/13309))

- Fix message endpoint not being settable ([#13311](https://github.com/vercel/vercel/pull/13311))

## 0.2.3

### Patch Changes

- Update readme and example ([#13307](https://github.com/vercel/vercel/pull/13307))

## 0.2.2

### Patch Changes

- Correct file output ([#13305](https://github.com/vercel/vercel/pull/13305))

## 0.2.1

### Patch Changes

- add in repository to readme and fix up example ([#13298](https://github.com/vercel/vercel/pull/13298))

## 0.2.0

### Minor Changes

- Publish initial version of mcp adapter ([#13290](https://github.com/vercel/vercel/pull/13290))

### Patch Changes

- make package public and fix default args passed in ([#13294](https://github.com/vercel/vercel/pull/13294))
