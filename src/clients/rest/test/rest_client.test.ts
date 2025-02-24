import '../../../test/test_helper';
import qs from 'qs';

import {ShopifyHeader} from '../../../base_types';
import {DataType, GetRequestParams} from '../../http_client/types';
import {assertHttpRequest} from '../../http_client/test/test_helper';
import {RestClient} from '../rest_client';
import {RestRequestReturn, PageInfo} from '../types';
import {Context} from '../../../context';
import * as ShopifyErrors from '../../../error';

const domain = 'test-shop.myshopify.io';
const successResponse = {
  products: [
    {
      title: 'Test title',
      amount: 10,
    },
  ],
};

describe('REST client', () => {
  it('can make GET request', async () => {
    const client = new RestClient(domain, 'dummy-token');

    fetchMock.mockResponseOnce(JSON.stringify(successResponse));

    await expect(client.get({path: 'products'})).resolves.toEqual(buildExpectedResponse(successResponse));
    assertHttpRequest({method: 'GET', domain, path: '/admin/api/unstable/products.json'});
  });

  it('can make GET request with path in query', async () => {
    const client = new RestClient(domain, 'dummy-token');

    fetchMock.mockResponseOnce(JSON.stringify(successResponse));
    const getRequest = {
      path: 'products',
      query: {
        path: 'some_path',
      },
    };

    await expect(client.get(getRequest)).resolves.toEqual(buildExpectedResponse(successResponse));
    assertHttpRequest({method: 'GET', domain, path: '/admin/api/unstable/products.json?path=some_path'});
  });

  it('can make POST request with JSON data', async () => {
    const client = new RestClient(domain, 'dummy-token');

    fetchMock.mockResponseOnce(JSON.stringify(successResponse));

    const postData = {
      title: 'Test product',
      amount: 10,
    };

    await expect(client.post({path: 'products', type: DataType.JSON, data: postData}))
      .resolves.toEqual(buildExpectedResponse(successResponse));

    assertHttpRequest({
      method: 'POST',
      domain,
      path: '/admin/api/unstable/products.json',
      headers: {'Content-Type': DataType.JSON.toString()},
      data: JSON.stringify(postData),
    });
  });

  it('can make POST request with form data', async () => {
    const client = new RestClient(domain, 'dummy-token');

    fetchMock.mockResponseOnce(JSON.stringify(successResponse));

    const postData = {
      title: 'Test product',
      amount: 10,
    };

    await expect(client.post({path: 'products', type: DataType.URLEncoded, data: postData}))
      .resolves.toEqual(buildExpectedResponse(successResponse));

    assertHttpRequest({
      method: 'POST',
      domain,
      path: '/admin/api/unstable/products.json',
      headers: {'Content-Type': DataType.URLEncoded.toString()},
      data: qs.stringify(postData),
    });
  });

  it('can make PUT request with JSON data', async () => {
    const client = new RestClient(domain, 'dummy-token');

    fetchMock.mockResponseOnce(JSON.stringify(successResponse));

    const putData = {
      title: 'Test product',
      amount: 10,
    };

    await expect(client.put({path: 'products/123', type: DataType.JSON, data: putData}))
      .resolves.toEqual(buildExpectedResponse(successResponse));

    assertHttpRequest({
      method: 'PUT',
      domain,
      path: '/admin/api/unstable/products/123.json',
      headers: {'Content-Type': DataType.JSON.toString()},
      data: JSON.stringify(putData),
    });
  });

  it('can make DELETE request', async () => {
    const client = new RestClient(domain, 'dummy-token');

    fetchMock.mockResponseOnce(JSON.stringify(successResponse));

    await expect(client.delete({path: 'products/123'}))
      .resolves.toEqual(buildExpectedResponse(successResponse));

    assertHttpRequest({method: 'DELETE', domain, path: '/admin/api/unstable/products/123.json'});
  });

  it('merges custom headers with the default ones', async () => {
    const client = new RestClient(domain, 'dummy-token');

    const customHeaders: Record<string, string> = {
      'X-Not-A-Real-Header': 'some_value',
    };

    fetchMock.mockResponseOnce(JSON.stringify(successResponse));

    await expect(client.get({path: 'products', extraHeaders: customHeaders})).resolves.toEqual(
      buildExpectedResponse(successResponse),
    );

    customHeaders[ShopifyHeader.AccessToken] = 'dummy-token';
    assertHttpRequest({method: 'GET', domain, path: '/admin/api/unstable/products.json', headers: customHeaders});
  });

  it('includes pageInfo of type PageInfo in the returned object for calls with next or previous pages', async () => {
    const params = getDefaultPageInfo();
    const client = new RestClient(domain, 'dummy-token');
    const linkHeaders = [
      `<${params.previousPageUrl}>; rel="previous"`,
      `<${params.nextPageUrl}>; rel="next"`,
      'This invalid info header will be ignored',
    ];

    fetchMock.mockResponses([JSON.stringify(successResponse), {headers: {link: linkHeaders.join(', ')}}]);

    const response = (await client.get({path: 'products', query: {limit: 10}})) as RestRequestReturn;

    expect(response).toHaveProperty('pageInfo');
    expect(response.pageInfo).toEqual(params);
  });

  it('is able to make subsequent get requests to either pageInfo.nextPage or pageInfo.prevPage', async () => {
    const params = getDefaultPageInfo();
    const client = new RestClient(domain, 'dummy-token');
    const linkHeaders = [`<${params.previousPageUrl}>; rel="previous"`, `<${params.nextPageUrl}>; rel="next"`];

    fetchMock.mockResponses(
      [JSON.stringify(successResponse), {headers: {link: linkHeaders.join(', ')}}],
      [JSON.stringify(successResponse), {headers: {link: linkHeaders.join(', ')}}],
      [JSON.stringify(successResponse), {headers: {link: linkHeaders.join(', ')}}],
    );

    const initialResponse = (await client.get({path: 'products', query: {limit: 10}})) as RestRequestReturn;

    const pageInfo = initialResponse.pageInfo as PageInfo;
    const nextPageResponse = await client.get(pageInfo.nextPage as GetRequestParams);
    expect(nextPageResponse).toBeDefined();
    expect(nextPageResponse).toHaveProperty('pageInfo');

    const prevPageResponse = await client.get(pageInfo.prevPage as GetRequestParams);
    expect(prevPageResponse).toBeDefined();
    expect(prevPageResponse).toHaveProperty('pageInfo');
  });

  it('can request next pages until they run out', async () => {
    const params = getDefaultPageInfo();
    const client = new RestClient(domain, 'dummy-token');
    const linkHeaders = [`<${params.previousPageUrl}>; rel="previous"`, `<${params.nextPageUrl}>; rel="next"`];

    fetchMock.mockResponses(
      [JSON.stringify(successResponse), {headers: {link: linkHeaders.join(', ')}}],
      [JSON.stringify(successResponse), {headers: {link: linkHeaders.join(', ')}}],
      [JSON.stringify(successResponse), {headers: {link: `<${params.previousPageUrl}>; rel="previous"`}}],
    );

    const initialResponse = (await client.get({path: 'products', query: {limit: 10}})) as RestRequestReturn;
    expect(initialResponse.pageInfo!.nextPageUrl).toBe(params.nextPageUrl);
    const secondResponse = (await client.get(initialResponse.pageInfo!.nextPage!)) as RestRequestReturn;
    expect(secondResponse.pageInfo!.nextPageUrl).toBe(params.nextPageUrl);
    const thirdResponse = (await client.get(secondResponse.pageInfo!.nextPage!)) as RestRequestReturn;
    expect(thirdResponse.pageInfo!.nextPageUrl).toBeUndefined();
    expect(thirdResponse.pageInfo!.nextPage).toBeUndefined();
  });

  it('can request previous pages until they run out', async () => {
    const params = getDefaultPageInfo();
    const client = new RestClient(domain, 'dummy-token');
    const linkHeaders = [`<${params.previousPageUrl}>; rel="previous"`, `<${params.nextPageUrl}>; rel="next"`];

    fetchMock.mockResponses(
      [JSON.stringify(successResponse), {headers: {link: linkHeaders.join(', ')}}],
      [JSON.stringify(successResponse), {headers: {link: linkHeaders.join(', ')}}],
      [JSON.stringify(successResponse), {headers: {link: `<${params.previousPageUrl}>; rel="next"`}}],
    );

    const initialResponse = (await client.get({path: 'products', query: {limit: 10}})) as RestRequestReturn;
    expect(initialResponse.pageInfo!.previousPageUrl).toBe(params.previousPageUrl);
    const secondResponse = (await client.get(initialResponse.pageInfo!.prevPage!)) as RestRequestReturn;
    expect(secondResponse.pageInfo!.previousPageUrl).toBe(params.previousPageUrl);
    const thirdResponse = (await client.get(secondResponse.pageInfo!.prevPage!)) as RestRequestReturn;
    expect(thirdResponse.pageInfo!.previousPageUrl).toBeUndefined();
    expect(thirdResponse.pageInfo!.prevPage).toBeUndefined();
  });

  it('adapts to private app requests', async () => {
    Context.IS_PRIVATE_APP = true;
    Context.initialize(Context);

    const client = new RestClient(domain);

    fetchMock.mockResponseOnce(JSON.stringify(successResponse));

    await expect(client.get({path: 'products'})).resolves.toEqual(buildExpectedResponse(successResponse));

    const customHeaders: Record<string, string> = {};
    customHeaders[ShopifyHeader.AccessToken] = 'test_secret_key';

    assertHttpRequest({
      method: 'GET',
      domain,
      path: '/admin/api/unstable/products.json',
      headers: customHeaders,
    });
  });

  it('fails to instantiate without access token', () => {
    expect(() => new RestClient(domain)).toThrow(ShopifyErrors.MissingRequiredArgument);
  });
});

function getDefaultPageInfo(): PageInfo {
  const limit = '10';
  const fields = ['test1', 'test2'];
  const previousUrl = `https://${domain}/admin/api/unstable/products.json?limit=${limit}&fields=${fields.join(
    ',',
  )}&page_info=previousToken`;
  const nextUrl = `https://${domain}/admin/api/unstable/products.json?limit=${limit}&fields=${fields.join(
    ',',
  )}&page_info=nextToken`;
  const prevPage = {
    path: 'products',
    // eslint-disable-next-line @typescript-eslint/naming-convention
    query: {fields: fields.join(','), limit: `${limit}`, page_info: 'previousToken'},
  };
  const nextPage = {
    path: 'products',
    // eslint-disable-next-line @typescript-eslint/naming-convention
    query: {fields: fields.join(','), limit: `${limit}`, page_info: 'nextToken'},
  };

  return {
    limit,
    fields,
    previousPageUrl: previousUrl,
    nextPageUrl: nextUrl,
    prevPage,
    nextPage,
  };
}

function buildExpectedResponse(obj: unknown, pageInfo?: PageInfo): RestRequestReturn {
  const expectedResponse: RestRequestReturn = {
    body: obj,
    headers: expect.objectContaining({}),
  };

  if (pageInfo) {
    expectedResponse.pageInfo = pageInfo;
  }

  return expect.objectContaining(expectedResponse);
}
