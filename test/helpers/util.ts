import { Request, request } from 'express';

export const noop = async (): Promise<undefined> => undefined;

export function createReq(props: unknown): Request {
  return Object.assign(request, props) as Request;
}
