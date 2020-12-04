import { request } from 'express';
import { cloneDeep } from 'lodash';

import { CommonRequestFields, ExpressRequestField, TokenRequestFields } from '../src/types';

export const noop = (): null => null;

export function createReq<
  Request extends CommonRequestFields & TokenRequestFields & ExpressRequestField
>(props: Request): Request {
  return Object.assign(cloneDeep(request), props);
}
