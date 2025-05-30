import { InvalidTokenError, InsufficientScopeError, ServerError } from '@modelcontextprotocol/sdk/server/auth/errors';
import { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types';

// Extend the Request type to include auth info
declare global {
  interface Request {
    auth?: AuthInfo;
  }
}
export interface McpAuthOptions {
  /**
   * Optional, scopes that the token must have.
   */
  requiredScopes?: string[];

  /**
   * Optional, resource metadata path to include in WWW-Authenticate header.
   */
  resourceMetadataPath?: string;
}

export function withMcpAuth(
  handler: (req: Request) => Promise<Response>,
  verifyToken: (req: Request, token: string) => Promise<AuthInfo>,
  options: McpAuthOptions = {
    resourceMetadataPath: "/.well-known/oauth-protected-resource"
  }
) {
  return async (req: Request) => {
    try {
      if (!req.headers.get("Authorization")) {
        throw new InvalidTokenError("Missing Authorization header");
      }

      const authHeader = req.headers.get("Authorization");
      const [type, token] = authHeader?.split(" ") || [];

      if (type?.toLowerCase() !== "bearer" || !token) {
        throw new InvalidTokenError("Invalid Authorization header format, expected 'Bearer TOKEN'");
      }

      let authInfo: AuthInfo;
      try {
        authInfo = await verifyToken(req, token);
      } catch (error) {
        // Handle any error from verifyToken as a 401
        throw new InvalidTokenError(
          error instanceof Error ? error.message : "Failed to verify token"
        );
      }

      // Check if token has the required scopes (if any)
      if (options.requiredScopes?.length) {
        const hasAllScopes = options.requiredScopes.every(scope =>
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
      req.auth = authInfo;

      return handler(req);
    } catch (error) {
      const origin = new URL(req.url).origin;
      const resourceMetadataUrl = options.resourceMetadataPath || `${origin}/.well-known/oauth-protected-resource`;
      
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
