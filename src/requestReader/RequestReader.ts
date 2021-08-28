export interface RequestReader {
  extractConnectJwt(): string;
  extractClientKey(): string;
  computeQueryStringHash(baseUrl: string): string;
}
