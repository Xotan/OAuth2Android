/*
 * The MIT License (MIT)
 * Copyright (c) 2011 Christoph Gerstner <development@christoph-gerstner.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Note: For questions or suggestions don't hesitate to contact me under the
 * above email address.
 */
package org.gerstner.oauth2android.common;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.List;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.gerstner.oauth2android.exception.InvalidClientException;
import org.gerstner.oauth2android.exception.InvalidGrantException;
import org.gerstner.oauth2android.exception.InvalidRequestException;
import org.gerstner.oauth2android.exception.InvalidScopeException;
import org.gerstner.oauth2android.exception.OAuthException;
import org.gerstner.oauth2android.exception.UnauthorizedClientException;
import org.gerstner.oauth2android.exception.UnsupportedGrantTypeException;
import org.gerstner.oauth2android.response.Response;

/**
 * The Connection class contains static methods used to connect to any url given.
 * In addition to the methods it holds predefined values that can be used to identify
 * the http-method in a standardized way.
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class Connection {

    /**
     * Usually this method is used when the client sends a resource (included
     * in the http body entity) to the server to place this resource under the
     * specified url.
     * @see #HTTP_METHOD_POST
     * @see #HTTP_METHOD_GET
     * @see #HTTP_METHOD_DELETE
     */
    final public static String HTTP_METHOD_PUT = "PUT";
    /**
     * This http methd can be used to transfer a resource or its modifications to the server.
     * When using this method the client agrees to implicit changes on the server side.
     * @see #HTTP_METHOD_PUT
     * @see #HTTP_METHOD_GET
     * @see #HTTP_METHOD_DELETE
     */
    final public static String HTTP_METHOD_POST = "POST";
    /**
     * This http method should only be used to retrieve informations from the server.
     * A client that uses this method does not automatically agree to making changes on
     * the server side.
     * @see #HTTP_METHOD_PUT
     * @see #HTTP_METHOD_POST
     * @see #HTTP_METHOD_DELETE
     */
    final public static String HTTP_METHOD_GET = "GET";
    /**
     * As the name already suggests, this method does not send any resources to the server
     * but makes the explicit request to delete the resource (and make implied changes)
     * the request is leading to.
     * @see #HTTP_METHOD_PUT
     * @see #HTTP_METHOD_POST
     * @see #HTTP_METHOD_GET
     */
    final public static String HTTP_METHOD_DELETE = "DELETE";

    /**
     *
     * Makes a standard http post request. The list of NameValuePairs can contain
     * all parameters and parameter designations for the request.
     *
     * @param parameterList
     * @param url
     * @return <code>Response</code> with the servers response
     * @throws UnsupportedEncodingException
     * @throws IOException
     */
    public static Response httpPostRequest(List<NameValuePair> parameterList, String url)
        throws InvalidRequestException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException, IOException {
        // prepare
        HttpClient httpclient = new DefaultHttpClient();            // client that executes the post request
        HttpPost httpPost = new HttpPost(url);                      // post request with the url
        try {
            httpPost.setEntity(new UrlEncodedFormEntity(parameterList)); // set entity with all parameters
        } catch (UnsupportedEncodingException ex) {
            // won't bw thrown
        }

        // request
        Response response = new Response(httpclient.execute(httpPost));

        // set original request url to response (not important)
        response.setRequestUrl(EntityUtils.toString(httpPost.getEntity()));

        return response;
    }

}
