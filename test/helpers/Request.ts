import { Request } from 'express';

export function createReq(props: unknown): Request {
  return Object.assign({}, props) as Request;
}
