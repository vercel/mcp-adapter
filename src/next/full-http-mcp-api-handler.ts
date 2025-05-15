import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  type IncomingHttpHeaders,
  IncomingMessage,
  type ServerResponse,
} from "node:http";
import { Socket } from "node:net";
import { Readable } from "node:stream";
import type { ServerOptions } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { BodyType } from "./server-response-adapter";

interface SerializedRequest {
  requestId: string;
  url: string;
  method: string;
  body: BodyType;
  headers: IncomingHttpHeaders;
}

type LogLevel = "log" | "error" | "warn" | "info" | "debug";

function createLogger(verboseLogs = false) {
  return {
    log: (...args: unknown[]) => {
      if (verboseLogs) console.log(...args);
    },
    error: (...args: unknown[]) => {
      if (verboseLogs) console.error(...args);
    },
    warn: (...args: unknown[]) => {
      if (verboseLogs) console.warn(...args);
    },
    info: (...args: unknown[]) => {
      if (verboseLogs) console.info(...args);
    },
    debug: (...args: unknown[]) => {
      if (verboseLogs) console.debug(...args);
    },
  };
}
/**
 * Configuration for the MCP handler.
 * @property redisUrl - The URL of the Redis instance to use for the MCP handler.
 * @property streamableHttpEndpoint - The endpoint to use for the streamable HTTP transport.
 * @property sseEndpoint - The endpoint to use for the SSE transport.
 * @property verboseLogs - If true, enables console logging.
 */
export type Config = {
  /**
   * The URL of the Redis instance to use for the MCP handler.
   * @default process.env.REDIS_URL || process.env.KV_URL
   */
  redisUrl?: string;
  /**
   * The endpoint to use for the streamable HTTP transport.
   * @deprecated Use `set basePath` instead.
   * @default "/mcp"
   */
  streamableHttpEndpoint?: string;
  /**
   * The maximum duration of an MCP request in seconds.
   * @default 60
   */
  maxDuration?: number;
  /**
   * If true, enables console logging.
   * @default false
   */
  verboseLogs?: boolean;
  /**
   * The base path to use for deriving endpoints.
   * If provided, endpoints will be derived from this path.
   * For example, if basePath is "/", that means your routing is:
   *  /app/[transport]/route.ts and then:
   * - streamableHttpEndpoint will be "/mcp"
   * - sseEndpoint will be "/sse"
   * - sseMessageEndpoint will be "/message"
   * @default ""
   */
  basePath?: string;
};

/**
 * Derives MCP endpoints from a base path.
 * @param basePath - The base path to derive endpoints from
 * @returns An object containing the derived endpoints
 */
function deriveEndpointsFromBasePath(basePath: string): {
  streamableHttpEndpoint: string;
} {
  // Remove trailing slash if present
  const normalizedBasePath = basePath.replace(/\/$/, "");

  return {
    streamableHttpEndpoint: `${normalizedBasePath}/mcp`,
  };
}
/**
 * Calculates the endpoints for the MCP handler.
 * @param config - The configuration for the MCP handler.
 * @returns An object containing the endpoints for the MCP handler.
 */
export function calculateEndpoints({
  basePath,
  streamableHttpEndpoint = "/mcp",
}: Config) {
  const { streamableHttpEndpoint: fullStreamableHttpEndpoint } =
    basePath != null
      ? deriveEndpointsFromBasePath(basePath)
      : {
          streamableHttpEndpoint,
        };

  return {
    streamableHttpEndpoint: fullStreamableHttpEndpoint,
  };
}

export function initializeMcpApiHandler(
  initializeServer: (server: McpServer) => void,
  serverOptions: ServerOptions = {},
  config: Config = {
    redisUrl: process.env.REDIS_URL || process.env.KV_URL,
    streamableHttpEndpoint: "/mcp",
    basePath: "",
    maxDuration: 60,
    verboseLogs: false,
  }
) {
  const {
    redisUrl,
    basePath,
    streamableHttpEndpoint: explicitStreamableHttpEndpoint,
    maxDuration,
    verboseLogs,
  } = config;

  // If basePath is provided, derive endpoints from it
  const { streamableHttpEndpoint } = calculateEndpoints({
    basePath,
    streamableHttpEndpoint: explicitStreamableHttpEndpoint,
  });

  const logger = createLogger(verboseLogs);

  let statelessServer: McpServer;
  const statelessTransport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });
  return async function mcpApiHandler(req: Request, res: ServerResponse) {
    const url = new URL(req.url || "", "https://example.com");
    if (url.pathname === streamableHttpEndpoint) {
      if (req.method === "GET") {
        logger.log("Received GET MCP request");
        res.writeHead(405).end(
          JSON.stringify({
            jsonrpc: "2.0",
            error: {
              code: -32000,
              message: "Method not allowed.",
            },
            id: null,
          })
        );
        return;
      }
      if (req.method === "DELETE") {
        logger.log("Received DELETE MCP request");
        res.writeHead(405).end(
          JSON.stringify({
            jsonrpc: "2.0",
            error: {
              code: -32000,
              message: "Method not allowed.",
            },
            id: null,
          })
        );
        return;
      }

      if (req.method === "POST") {
        logger.log("Got new MCP connection", req.url, req.method);

        if (!statelessServer) {
          statelessServer = new McpServer(
            {
              name: "mcp-typescript server on vercel",
              version: "0.1.0",
            },
            serverOptions
          );

          initializeServer(statelessServer);
          await statelessServer.connect(statelessTransport);
        }

        // Parse the request body
        let bodyContent: BodyType;
        const contentType = req.headers.get("content-type") || "";
        if (contentType.includes("application/json")) {
          bodyContent = await req.json();
        } else {
          bodyContent = await req.text();
        }

        const incomingRequest = createFakeIncomingMessage({
          method: req.method,
          url: req.url,
          headers: Object.fromEntries(req.headers),
          body: bodyContent,
        });
        await statelessTransport.handleRequest(incomingRequest, res);
      }
    } else {
      logger.log("Received request for", url.pathname);
      res.writeHead(404).end(
        JSON.stringify({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: `${url.pathname} not found.`,
          },
          id: null,
        })
      );
    }
  };
}

// Define the options interface
interface FakeIncomingMessageOptions {
  method?: string;
  url?: string;
  headers?: IncomingHttpHeaders;
  body?: BodyType;
  socket?: Socket;
}

// Create a fake IncomingMessage
function createFakeIncomingMessage(
  options: FakeIncomingMessageOptions = {}
): IncomingMessage {
  const {
    method = "GET",
    url = "/",
    headers = {},
    body = null,
    socket = new Socket(),
  } = options;

  // Create a readable stream that will be used as the base for IncomingMessage
  const readable = new Readable();
  readable._read = (): void => {}; // Required implementation

  // Add the body content if provided
  if (body) {
    if (typeof body === "string") {
      readable.push(body);
    } else if (Buffer.isBuffer(body)) {
      readable.push(body);
    } else {
      // Ensure proper JSON-RPC format
      const bodyString = JSON.stringify(body);
      readable.push(bodyString);
    }
    readable.push(null); // Signal the end of the stream
  } else {
    readable.push(null); // Always end the stream even if no body
  }

  // Create the IncomingMessage instance
  const req = new IncomingMessage(socket);

  // Set the properties
  req.method = method;
  req.url = url;
  req.headers = headers;

  // Copy over the stream methods
  req.push = readable.push.bind(readable);
  req.read = readable.read.bind(readable);
  // @ts-expect-error
  req.on = readable.on.bind(readable);
  req.pipe = readable.pipe.bind(readable);

  return req;
}
