import { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types";
import { InvalidTokenError, InsufficientScopeError, ServerError } from "@modelcontextprotocol/sdk/server/auth/errors";
import { withAuthContext } from "./auth-context";

export function withMcpAuth(
  handler: (req: Request) => Response | Promise<Response>,
  verifyToken: (
    req: Request,
    bearerToken?: string
  ) => AuthInfo | undefined | Promise<AuthInfo | undefined>,
  {
    required = false,
    resourceMetadataPath = "/.well-known/oauth-protected-resource",
    requiredScopes,
  }: {
    required?: boolean;
    resourceMetadataPath?: string;
    requiredScopes?: string[];
  } = {}
) {
  return async (req: Request) => {
    try {
      const authHeader = req.headers.get("Authorization");
      const [type, token] = authHeader?.split(" ") || [];

      // Only support bearer token as per the MCP spec
      // https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization#2-6-1-token-requirements
      const bearerToken = type?.toLowerCase() === "bearer" ? token : undefined;

      const authInfo = await verifyToken(req, bearerToken);
      
      if (required && !authInfo) {
        throw new InvalidTokenError("No authorization provided");
      }

      if (!authInfo) {
        return handler(req);
      }

      // Check if token has the required scopes (if any)
      if (requiredScopes?.length) {
        const hasAllScopes = requiredScopes.every(scope =>
          authInfo.scopes.includes(scope)
        );

        if (!hasAllScopes) {
          throw new InsufficientScopeError("Insufficient scope");
        }
      }

      // Check if the token is expired
      if (authInfo.expiresAt && authInfo.expiresAt < Date.now() / 1000) {
        throw new InvalidTokenError("Token has expired");
      }

      // Set auth info on the request object after successful verification
      (req as any).auth = authInfo;

      return withAuthContext(authInfo, () => handler(req));
    } catch (error) {
      const origin = new URL(req.url).origin;
      const resourceMetadataUrl = `${origin}${resourceMetadataPath}`;

      if (error instanceof InvalidTokenError) {
        return new Response(JSON.stringify(error.toResponseObject()), {
          status: 401,
          headers: {
            "WWW-Authenticate": `Bearer error="${error.errorCode}", error_description="${error.message}", resource_metadata="${resourceMetadataUrl}"`,
            "Content-Type": "application/json"
          }
        });
      } else if (error instanceof InsufficientScopeError) {
        return new Response(JSON.stringify(error.toResponseObject()), {
          status: 403,
          headers: {
            "WWW-Authenticate": `Bearer error="${error.errorCode}", error_description="${error.message}", resource_metadata="${resourceMetadataUrl}"`,
            "Content-Type": "application/json"
          }
        });
      } else if (error instanceof ServerError) {
        return new Response(JSON.stringify(error.toResponseObject()), {
          status: 500,
          headers: {
            "Content-Type": "application/json"
          }
        });
      } else {
        console.error("Unexpected error authenticating bearer token:", error);
        const serverError = new ServerError("Internal Server Error");
        return new Response(JSON.stringify(serverError.toResponseObject()), {
          status: 500,
          headers: {
            "Content-Type": "application/json"
          }
        });
      }
    }
  };
}


