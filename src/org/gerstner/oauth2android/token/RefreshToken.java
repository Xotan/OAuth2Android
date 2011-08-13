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
package org.gerstner.oauth2android.token;

import android.util.Base64;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.http.Header;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.gerstner.oauth2android.Client;
import org.gerstner.oauth2android.Server;
import org.gerstner.oauth2android.common.Connection;
import org.gerstner.oauth2android.exception.InvalidClientException;
import org.gerstner.oauth2android.exception.InvalidGrantException;
import org.gerstner.oauth2android.exception.InvalidRequestException;
import org.gerstner.oauth2android.exception.InvalidScopeException;
import org.gerstner.oauth2android.exception.OAuthException;
import org.gerstner.oauth2android.exception.UnauthorizedClientException;
import org.gerstner.oauth2android.exception.UnsupportedGrantTypeException;
import org.gerstner.oauth2android.response.Response;

/**
 * The <code>RefreshToken</code> is of no special kind. It is simply a String
 * with wich it is possible to retrieve another access token.
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class RefreshToken
    extends Token {

    private HttpUriRequest authorizedHttpGet;

    /**
     * Creates a new instance of a RefreshToken
     * @param token <code>string</code> the refresh token
     */
    public RefreshToken(String token) {
        super(token);
        super.setType("RefreshToken");
    }

    /**
     * This method is special for the RefreshToken. It makes an authorized request to
     * the TokenEndpoint (AccessTokenServer) to request a new AccessToken. Therefore
     * it presents the RefreshToken in a basic http Authorization Header. <br>
     * You may use GET for the http Method, but it is recommended to use POST. If
     * the <code>method</code> parameter is empty POST will be used.<br>
     * The result is an Response-Instance containing the new Access-Token or throwing
     * an Exception if the server responds with an error.
     * @param client <code>Client</code> of this application
     * @param server <code>Server</code> Instance with the service-providers endpoints
     * @param method <code>String</code> value of the http-method used.
     * @return the <code>Response</code> of the request containing the AccessToken
     * @throws InvalidRequestException the request is missing a parameter or is otherwise invalid
     * @throws InvalidClientException the client could not be identified
     * @throws InvalidGrantException the authorization grant is not valid
     * @throws UnauthorizedClientException the token is not valid or is of the wrong type
     * @throws UnsupportedGrantTypeException the client used an unsupported method for the authorization grant
     * @throws InvalidScopeException the scope is incomplete or invalid
     * @throws OAuthException if this is catched, no other {@link org.gerstner.oauth2android.exception.OAuthException} extending Exception will be thrown.
     * @throws IOException a connection error occurred during the request
     */
    public Response executeRefreshRequest(Client client, Server server, String method)
        throws IOException, InvalidRequestException, InvalidClientException, InvalidGrantException, UnauthorizedClientException, UnsupportedGrantTypeException, InvalidScopeException, OAuthException {
        HttpClient httpClient = new DefaultHttpClient();
        Response response;
        if (method == null) {
            method = "";
        }
        if (method.equalsIgnoreCase(Connection.HTTP_METHOD_GET)) {
            String parameterString = "grant_type=refresh_token&client_id=" + client.getClientID() + "&refresh_token=" + this.getToken();
            HttpGet httpGet = new HttpGet(server.getAccessTokenServer() + "?" + parameterString);

            String authorization = Base64.encodeToString((client.getClientID() + ":" + client.getClientSecret()).getBytes(), Base64.DEFAULT);
            Header header = new BasicHeader("Authorization", "Basic " + authorization);
            httpGet.addHeader(header);

            response = new Response(httpClient.execute(httpGet));

        } else {
            HttpPost httpPost = new HttpPost(server.getAccessTokenServer());
            httpPost.addHeader("Content-Type", "application/x-www-form-urlencoded");

            List<NameValuePair> parameterList = new ArrayList<NameValuePair>();
            parameterList.add(new BasicNameValuePair("grant_type", "refresh_token"));
            parameterList.add(new BasicNameValuePair("client_id", client.getClientID()));
            parameterList.add(new BasicNameValuePair("refresh_token", this.getToken()));
            httpPost.setEntity(new UrlEncodedFormEntity(parameterList));

            response = new Response(httpClient.execute(httpPost));
        }

        return response;
    }
}
