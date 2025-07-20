import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  type IncomingHttpHeaders,
  IncomingMessage,
  type ServerResponse,
} from "node:http";
import { createClient } from "redis";
import { Socket } from "node:net";
import { Readable } from "node:stream";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { BodyType } from "./server-response-adapter";
import assert from "node:assert";
import type {
  McpEvent,
  McpErrorEvent,
  McpSessionEvent,
  McpRequestEvent,
} from "../lib/log-helper";
import { createEvent } from "../lib/log-helper";
import { EventEmittingResponse } from "../lib/event-emitter.js";
import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types";
import { getAuthContext } from "../auth/auth-context";
import { ServerOptions } from ".";
import { Logger, LogLevel, createDefaultLogger } from "../types/logger";

interface SerializedRequest {
  requestId: string;
  url: string;
  method: string;
  body: BodyType;
  headers: IncomingHttpHeaders;
}
/**
 * Configuration for the MCP handler.
 * @property redisUrl - The URL of the Redis instance to use for the MCP handler.
 * @property streamableHttpEndpoint - The endpoint to use for the streamable HTTP transport.
 * @property sseEndpoint - The endpoint to use for the SSE transport.
 * @property verboseLogs - If true, enables console logging.
 * @property logger - Custom logger implementation. If provided, takes precedence over verboseLogs.
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
   * The endpoint to use for the SSE transport.
   * @deprecated Use `set basePath` instead.
   * @default "/sse"
   */
  sseEndpoint?: string;
  /**
   * The endpoint to use for the SSE messages transport.
   * @deprecated Use `set basePath` instead.
   * @default "/message"
   */
  sseMessageEndpoint?: string;
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
  /**
   * Callback function that receives MCP events.
   * This can be used to track analytics, debug issues, or implement custom behaviors.
   */
  onEvent?: (event: McpEvent) => void;

  /**
   * If true, disables the SSE endpoint.
   * As of 2025-03-26, SSE is not supported by the MCP spec.
   * https://modelcontextprotocol.io/specification/2025-03-26/basic/transports
   * @default false
   */
  disableSse?: boolean;

  /**
   * Custom logger implementation.
   * If provided, this logger will be used instead of the default console logger.
   * Takes precedence over the verboseLogs option.
   */
  logger?: Logger;
};

/**
 * Derives MCP endpoints from a base path.
 * @param basePath - The base path to derive endpoints from
 * @returns An object containing the derived endpoints
 */
function deriveEndpointsFromBasePath(basePath: string): {
  streamableHttpEndpoint: string;
  sseEndpoint: string;
  sseMessageEndpoint: string;
} {
  // Remove trailing slash if present
  const normalizedBasePath = basePath.replace(/\/$/, "");

  return {
    streamableHttpEndpoint: `${normalizedBasePath}/mcp`,
    sseEndpoint: `${normalizedBasePath}/sse`,
    sseMessageEndpoint: `${normalizedBasePath}/message`,
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
  sseEndpoint = "/sse",
  sseMessageEndpoint = "/message",
}: Config) {
  const {
    streamableHttpEndpoint: fullStreamableHttpEndpoint,
    sseEndpoint: fullSseEndpoint,
    sseMessageEndpoint: fullSseMessageEndpoint,
  } = basePath != null
    ? deriveEndpointsFromBasePath(basePath)
    : {
        streamableHttpEndpoint,
        sseEndpoint,
        sseMessageEndpoint,
      };

  return {
    streamableHttpEndpoint: fullStreamableHttpEndpoint,
    sseEndpoint: fullSseEndpoint,
    sseMessageEndpoint: fullSseMessageEndpoint,
  };
}

let redisPublisher: ReturnType<typeof createClient>;
let redis: ReturnType<typeof createClient>;

async function initializeRedis({
  redisUrl,
  logger,
}: {
  redisUrl?: string;
  logger: Logger;
}) {
  if (redis && redisPublisher) {
    return { redis, redisPublisher };
  }

  if (!redisUrl) {
    throw new Error("redisUrl is required");
  }

  redis = createClient({
    url: redisUrl,
  });
  redisPublisher = createClient({
    url: redisUrl,
  });
  redis.on("error", (err) => {
    logger.error("Redis error", err);
  });
  redisPublisher.on("error", (err) => {
    logger.error("Redis error", err);
  });

  await Promise.all([redis.connect(), redisPublisher.connect()]);

  return { redis, redisPublisher };
}

export function initializeMcpApiHandler(
  initializeServer:
    | ((server: McpServer) => Promise<void>)
    | ((server: McpServer) => void),
  serverOptions: ServerOptions = {},
  config: Config = {
    redisUrl: process.env.REDIS_URL || process.env.KV_URL,
    streamableHttpEndpoint: "/mcp",
    sseEndpoint: "/sse",
    sseMessageEndpoint: "/message",
    basePath: "",
    maxDuration: 60,
    verboseLogs: false,
    disableSse: false,
  }
) {
  const {
    redisUrl,
    basePath,
    streamableHttpEndpoint: explicitStreamableHttpEndpoint,
    sseEndpoint: explicitSseEndpoint,
    sseMessageEndpoint: explicitSseMessageEndpoint,
    maxDuration,
    verboseLogs,
    disableSse,
  } = config;

  const {
    serverInfo = {
      name: "mcp-typescript server on vercel",
      version: "0.1.0",
    },
    ...mcpServerOptions
  } = serverOptions;

  // If basePath is provided, derive endpoints from it
  const { streamableHttpEndpoint, sseEndpoint, sseMessageEndpoint } =
    calculateEndpoints({
      basePath,
      streamableHttpEndpoint: explicitStreamableHttpEndpoint,
      sseEndpoint: explicitSseEndpoint,
      sseMessageEndpoint: explicitSseMessageEndpoint,
    });

  const logger = config.logger || createDefaultLogger({ verboseLogs });

  let servers: McpServer[] = [];

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
        const eventRes = new EventEmittingResponse(
          createFakeIncomingMessage(),
          config.onEvent
        );

        if (!statelessServer) {
          statelessServer = new McpServer(serverInfo, mcpServerOptions);
          await initializeServer(statelessServer);
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
          auth: req.auth, // Use the auth info that should already be set by withMcpAuth
        });

        // Create a response that will emit events
        const wrappedRes = new EventEmittingResponse(
          incomingRequest,
          config.onEvent
        );
        Object.assign(wrappedRes, res);

        try {
          await statelessTransport.handleRequest(incomingRequest, wrappedRes);
          if (
            typeof bodyContent === "object" &&
            bodyContent &&
            "method" in bodyContent
          ) {
            eventRes.requestCompleted(
              bodyContent.method as string,
              bodyContent
            );
          }
        } catch (error) {
          if (
            typeof bodyContent === "object" &&
            bodyContent &&
            "method" in bodyContent
          ) {
            eventRes.requestCompleted(
              bodyContent.method as string,
              undefined,
              error instanceof Error ? error : String(error)
            );
          }
          throw error;
        }
      }
    } else if (url.pathname === sseEndpoint) {
      if (disableSse) {
        res.statusCode = 404;
        res.end("Not found");
        return;
      }

      // Check HTTP method - only allow GET for SSE connections
      if (req.method !== "GET") {
        logger.log(`Rejected SSE connection with method ${req.method}`);
        res
          .writeHead(405, { "Content-Type": "text/plain" })
          .end("Method Not Allowed");
        return;
      }

      // Check that Accept header supports event-stream
      const acceptHeader =
        req.headers.get("accept") || req.headers.get("Accept");
      if (
        acceptHeader &&
        !acceptHeader.includes("text/event-stream") &&
        !acceptHeader.includes("*/*") &&
        !acceptHeader.includes("text/*")
      ) {
        logger.log(
          `Rejected SSE connection with incompatible Accept header: ${acceptHeader}`
        );
        res
          .writeHead(406, { "Content-Type": "text/plain" })
          .end("Not Acceptable");
        return;
      }

      const { redis, redisPublisher } = await initializeRedis({
        redisUrl,
        logger,
      });
      logger.log("Got new SSE connection");
      assert(sseMessageEndpoint, "sseMessageEndpoint is required");
      const transport = new SSEServerTransport(sseMessageEndpoint, res);
      const sessionId = transport.sessionId;

      const eventRes = new EventEmittingResponse(
        createFakeIncomingMessage(),
        config.onEvent,
        sessionId
      );
      eventRes.startSession("SSE", {
        userAgent: req.headers.get("user-agent") ?? undefined,
        ip:
          req.headers.get("x-forwarded-for") ??
          req.headers.get("x-real-ip") ??
          undefined,
      });

      const server = new McpServer(serverInfo, serverOptions);
      await initializeServer(server);

      servers.push(server);

      server.server.onclose = () => {
        logger.log("SSE connection closed");
        eventRes.endSession("SSE");
        servers = servers.filter((s) => s !== server);
      };

      let logs: {
        type: LogLevel;
        messages: string[];
      }[] = [];

      // eslint-disable-next-line no-inner-declarations
      function logInContext(severity: LogLevel, ...messages: string[]) {
        logs.push({
          type: severity,
          messages,
        });
      }

      // Handles messages originally received via /message
      const handleMessage = async (message: string) => {
        logger.log("Received message from Redis", message);
        logInContext("log", "Received message from Redis", message);
        const request = JSON.parse(message) as SerializedRequest;

        // Make in IncomingMessage object because that is what the SDK expects.
        const req = createFakeIncomingMessage({
          method: request.method,
          url: request.url,
          headers: request.headers,
          body: request.body,
        });

        const syntheticRes = new EventEmittingResponse(
          req,
          config.onEvent,
          sessionId
        );
        let status = 100;
        let body = "";
        syntheticRes.writeHead = (statusCode: number) => {
          status = statusCode;
          return syntheticRes;
        };
        syntheticRes.end = (b: unknown) => {
          body = b as string;
          return syntheticRes;
        };

        try {
          await transport.handlePostMessage(req, syntheticRes);

          // If it was a function call, complete it
          if (
            typeof request.body === "object" &&
            request.body &&
            "method" in request.body
          ) {
            try {
              const result = JSON.parse(body);
              eventRes.requestCompleted(request.body.method as string, result);
            } catch {
              eventRes.requestCompleted(request.body.method as string, body);
            }
          }
        } catch (error) {
          eventRes.error(
            error instanceof Error ? error : String(error),
            "Error handling SSE message",
            "session"
          );
          throw error;
        }

        await redisPublisher.publish(
          `responses:${sessionId}:${request.requestId}`,
          JSON.stringify({
            status,
            body,
          })
        );

        if (status >= 200 && status < 300) {
          logInContext(
            "log",
            `Request ${sessionId}:${request.requestId} succeeded: ${body}`
          );
        } else {
          logInContext(
            "error",
            `Message for ${sessionId}:${request.requestId} failed with status ${status}: ${body}`
          );
          eventRes.error(
            `Request failed with status ${status}`,
            body,
            "session"
          );
        }
      };

      const interval = setInterval(() => {
        for (const log of logs) {
          logger[log.type](...log.messages);
        }
        logs = [];
      }, 100);

      await redis.subscribe(`requests:${sessionId}`, handleMessage);
      logger.log(`Subscribed to requests:${sessionId}`);

      let timeout: NodeJS.Timeout;
      let resolveTimeout: (value: unknown) => void;
      const waitPromise = new Promise((resolve) => {
        resolveTimeout = resolve;
        timeout = setTimeout(() => {
          resolve("max duration reached");
        }, (maxDuration ?? 60) * 1000);
      });

      // eslint-disable-next-line no-inner-declarations
      async function cleanup() {
        clearTimeout(timeout);
        clearInterval(interval);
        await redis.unsubscribe(`requests:${sessionId}`, handleMessage);
        logger.log("Done");
        res.statusCode = 200;
        res.end();
      }
      req.signal.addEventListener("abort", () =>
        resolveTimeout("client hang up")
      );

      await server.connect(transport);
      const closeReason = await waitPromise;
      logger.log(closeReason);
      await cleanup();
    } else if (url.pathname === sseMessageEndpoint) {
      if (disableSse) {
        res.statusCode = 404;
        res.end("Not found");
        return;
      }

      const { redis, redisPublisher } = await initializeRedis({
        redisUrl,
        logger,
      });
      logger.log("Received message");

      const body = await req.text();
      let parsedBody: BodyType;
      try {
        parsedBody = JSON.parse(body);
      } catch (e) {
        parsedBody = body;
      }

      const sessionId = url.searchParams.get("sessionId") || "";
      if (!sessionId) {
        res.statusCode = 400;
        res.end("No sessionId provided");
        return;
      }
      const requestId = crypto.randomUUID();
      const serializedRequest: SerializedRequest = {
        requestId,
        url: req.url || "",
        method: req.method || "",
        body: parsedBody,
        headers: Object.fromEntries(req.headers.entries()),
      };

      // Declare timeout and response handling state before subscription
      let timeout: NodeJS.Timeout;
      let hasResponded = false;
      // Safe response handler to prevent double res.end()
      const sendResponse = (status: number, body: string) => {
        if (!hasResponded) {
          hasResponded = true;
          clearTimeout(timeout);
          res.statusCode = status;
          res.end(body);
        }
      };

      // Handles responses from the /sse endpoint.
      await redis.subscribe(
        `responses:${sessionId}:${requestId}`,
        (message) => {
          try {
            const response = JSON.parse(message) as {
              status: number;
              body: string;
            };
            sendResponse(response.status, response.body);
          } catch (error) {
            logger.error("Failed to parse response message:", error);
            sendResponse(500, "Internal server error");
          }
        }
      );

      // Queue the request in Redis so that a subscriber can pick it up.
      // One queue per session.
      await redisPublisher.publish(
        `requests:${sessionId}`,
        JSON.stringify(serializedRequest)
      );
      logger.log(`Published requests:${sessionId}`, serializedRequest);

      // Set timeout after subscription is established
      timeout = setTimeout(async () => {
        await redis.unsubscribe(`responses:${sessionId}:${requestId}`);
        sendResponse(408, "Request timed out");
      }, 10 * 1000);

      res.on("close", async () => {
        hasResponded = true;
        clearTimeout(timeout);
        await redis.unsubscribe(`responses:${sessionId}:${requestId}`);
      });
    } else {
      res.statusCode = 404;
      res.end("Not found");
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
  auth?: AuthInfo;
}

// Create a fake IncomingMessage
function createFakeIncomingMessage(
  options: FakeIncomingMessageOptions = {}
): IncomingMessage & { auth?: AuthInfo } {
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
  const req = new IncomingMessage(socket) as IncomingMessage & {
    auth?: AuthInfo;
  };

  // Set the properties
  req.method = method;
  req.url = url;
  req.headers = headers;

  const auth = options.auth || getAuthContext();
  if (auth) {
    // See https://github.com/modelcontextprotocol/typescript-sdk/blob/590d4841373fc4eb86ecc9079834353a98cb84a3/src/server/auth/middleware/bearerAuth.ts#L71 for more info.
    (req as { auth?: AuthInfo }).auth = auth;
  }

  // Copy over the stream methods
  req.push = readable.push.bind(readable);
  req.read = readable.read.bind(readable);
  // @ts-expect-error
  req.on = readable.on.bind(readable);
  req.pipe = readable.pipe.bind(readable);

  return req;
}
