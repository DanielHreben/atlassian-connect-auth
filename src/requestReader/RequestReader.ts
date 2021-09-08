/**
 * This interface is used by the library to obtain information about HTTP requests so they can
 * be verified. Implement it to adapt this library to any HTTP framework or library of your preference.
 */
export interface RequestReader {
  /**
   * Should extract the JWT from the `Authorization` header or the `jwt` query parameter (deprecated).
   * See: https://developer.atlassian.com/cloud/jira/platform/understanding-jwt-for-connect-apps/
   */
  extractConnectJwt(): string;

  /**
   * Should extract the `clientKey` attribute from the request body.
   * The Client Key is the Connect App's main installation identifier.
   */
  extractClientKey(): string;

  /**
   * Should compute the Query String Hash for the incoming request.
   * See: https://developer.atlassian.com/cloud/bitbucket/query-string-hash/
   */
  computeQueryStringHash(baseUrl: string): string;
}
