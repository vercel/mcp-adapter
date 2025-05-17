# @vercel/mcp-adapter

A Vercel adapter for the Model Context Protocol (MCP), enabling real-time communication between your applications and AI models. Currently supports Next.js with more framework adapters coming soon.

Currently uses `**@modelcontextprotocol/sdk@1.10.2**`

## Installation

```bash
npm install @vercel/mcp-adapter
# or
yarn add @vercel/mcp-adapter
# or
pnpm add @vercel/mcp-adapter
# or
bun add @vercel/mcp-adapter
```

## Next.js Usage

```typescript
// app/api/[transport]/route.ts
import { createMcpHandler } from '@vercel/mcp-adapter';
const handler = createMcpHandler(
  server => {
    server.tool(
      'roll_dice',
      'Rolls an N-sided die',
      { 
        sides: z.number().int().min(2)
      },
      async ({ sides }) => {
        const value = 1 + Math.floor(Math.random() * sides);
        return {
          content: [{ type: 'text', text: `🎲 You rolled a ${value}!` }],
        };
      }
    );
  },
  {
    // Optional server options
  },
  {
    // Optional redis config
    redisUrl: process.env.REDIS_URL,
    // You need these endpoints
    basePath: '/api', // this needs to match where the [transport] is located.
    maxDuration: 60,
    verboseLogs: true,
  }
);
export { handler as GET, handler as POST };
```

## Integrating into your client

When you want to use it in your MCP client of choice:

### Claude Desktop
[Official Docs](https://modelcontextprotocol.io/quickstart/user)

In order to add an MCP server to Claude Desktop you need to edit the configuration file located at:

```json
"remote-example": {
  "command": "npx",
  "args": [
    "mcp-remote",
    "http://localhost:3000/api/mcp" // this is your app/api/[transport]/route.ts
  ]
}
```

macOS: ~/Library/Application Support/Claude/claude_desktop_config.json
Windows: %APPDATA%\Claude\claude_desktop_config.json
If it does not exist yet, you may need to enable it under Settings > Developer.

Restart Claude Desktop to pick up the changes in the configuration file. Upon restarting, you should see a hammer icon in the bottom right corner of the input box.

### Cursor
[Official Docs](https://docs.cursor.com/context/model-context-protocol) 

The configuration file is located at ~/.cursor/mcp.json.

As of version 0.48.0, Cursor supports unauthed SSE servers directly. If your MCP server is using the official MCP OAuth authorization protocol, you still need to add a "command" server and call mcp-remote.

### Windsurf
[Official Docs](https://docs.codeium.com/windsurf/mcp)

The configuration file is located at ~/.codeium/windsurf/mcp_config.json.

## Usage in your app

1. Use the MCP client in your application:

```typescript
// app/components/YourComponent.tsx
import { McpClient } from '@modelcontextprotocol/sdk/client';

const client = new McpClient({
  // When using basePath, the SSE endpoint will be automatically derived
  transport: new SSEClientTransport('/api/mcp/mcp'),
});

// Use the client to make requests
const result = await client.request('yourMethod', { param: 'value' });
```

## Configuration Options

The `initializeMcpApiHandler` function accepts the following configuration options:

```typescript
interface Config {
  redisUrl?: string; // Redis connection URL for pub/sub
  // @deprecated use streamableHttpEndpoint, sseEndpoint, sseMessageEndpoint
  basePath?: string; // string; // Base path for MCP endpoints
  
  streamableHttpEndpoint?: string; // Endpoint for streamable HTTP transport
  sseEndpoint?: string; // Endpoint for SSE transport
  sseMessageEndpoint?: string; // Endpoint for SSE message transport
  maxDuration?: number; // Maximum duration for SSE connections in seconds
  verboseLogs?: boolean; // Log debugging information
}
```

## Features

- **Framework Support**: Currently supports Next.js with more framework adapters coming soon
- **Multiple Transport Options**: Supports both Streamable HTTP and Server-Sent Events (SSE) transports
- **Redis Integration**: For SSE transport resumability
- **TypeScript Support**: Full TypeScript support with type definitions

## Requirements

- Next.js 13 or later (for Next.js adapter)
- Node.js 18 or later
- Redis (optional, for SSE transport)

## License

MIT
