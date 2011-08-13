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

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import org.apache.http.Header;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.gerstner.oauth2android.Client;
import org.gerstner.oauth2android.Server;
import org.gerstner.oauth2android.exception.InvalidTokenTypeException;

/**
 * The <code>BearerTokenTypeDefinition</code> serves as the configuration class to define attributes of
 * bearer tokens.<br>
 * Bearer Tokens are very rudemental and only have most common, basic token attributes as there are:
 * the token String itself, a lifetime and if needed a scope. 
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 * @see org.gerstner.oauth2android.token.MacTokenTypeDefinition
 */
public class BearerTokenTypeDefinition
    extends TokenTypeDefinition {

    @Override
    public Token getEmptyToken() {
        return new BearerToken();
    }

    @Override
    public List<String> getAdditionalTokenParameters() {
        List<String> tokenAttributes = new ArrayList<String>(0);
        return tokenAttributes;
    }

    @Override
    public String getName() {
        return "bearer";
    }

    @Override
    public String requestProtectedResource(Token token, Client client, Server server, String resourceEndpoint, String body) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getHttpAuthenticationScheme() {
        return "BEARER";
    }

    @Override
    public HttpGet getAuthorizedHttpGet(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException {
        BearerToken token = castToken(client);

        HttpGet httpGet;

        String url = server.getResourceServer() + (requestUri.startsWith("/") ? requestUri : "/" + requestUri);
        if (!additionalParameter.isEmpty()) {
            if (url.contains("?")) {
                url += "&";
            } else {
                url += "?";
            }
            for (Iterator<NameValuePair> it = additionalParameter.iterator(); it.hasNext();) {
                NameValuePair nameValuePair = it.next();
                url += nameValuePair.getName() + "=" + nameValuePair.getValue();
                if (it.hasNext()) {
                    url += "&";
                }
            }
        }
        if (useHeader) {
            httpGet = new HttpGet(url);
            httpGet.addHeader(authorizationHeader(token));
        } else {
            if (url.contains("?")) {
                url += "&access_token=" + token.getToken();
            } else {
                url += "?access_token=" + token.getToken();
            }
            httpGet = new HttpGet(url);
        }
        return httpGet;
    }
    @Override
    public HttpDelete getAuthorizedHttpDelete(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException {
        BearerToken token = castToken(client);

        HttpDelete httpDelete;

        String url = server.getResourceServer() + (requestUri.startsWith("/") ? requestUri : "/" + requestUri);
        if (!additionalParameter.isEmpty()) {
            if (url.contains("?")) {
                url += "&";
            } else {
                url += "?";
            }
            for (Iterator<NameValuePair> it = additionalParameter.iterator(); it.hasNext();) {
                NameValuePair nameValuePair = it.next();
                url += nameValuePair.getName() + "=" + nameValuePair.getValue();
                if (it.hasNext()) {
                    url += "&";
                }
            }
        }
        if (useHeader) {
            httpDelete = new HttpDelete(url);
            httpDelete.addHeader(authorizationHeader(token));
        } else {
            if (url.contains("?")) {
                url += "&access_token=" + token.getToken();
            } else {
                url += "?access_token=" + token.getToken();
            }
            httpDelete = new HttpDelete(url);
        }
        return httpDelete;
    }

    @Override
    public HttpPost getAuthorizedHttpPost(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException {

        if (additionalParameter == null) {
            additionalParameter = new ArrayList<NameValuePair>();
        }

        BearerToken token = castToken(client);
        String url = server.getResourceServer() + (requestUri.startsWith("/") ? requestUri : "/" + requestUri);
        HttpPost httpPost = new HttpPost(url);

        if (useHeader) {
            httpPost.addHeader(authorizationHeader(token));

        } else {
            additionalParameter.add(new BasicNameValuePair("access_token", token.getToken()));
        }
        if (!additionalParameter.isEmpty()) {

            httpPost.addHeader("Content-Type", "application/x-www-form-urlencoded");
            try {
                httpPost.setEntity(new UrlEncodedFormEntity(additionalParameter));
            } catch (UnsupportedEncodingException ex) {
                // TODO: invalid url exceptions ????
            }
        }
        return httpPost;
    }

    @Override
    public HttpPut getAuthorizedHttpPut(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException {

        if (additionalParameter == null) {
            additionalParameter = new ArrayList<NameValuePair>();
        }

        BearerToken token = castToken(client);
        String url = server.getResourceServer() + (requestUri.startsWith("/") ? requestUri : "/" + requestUri);
        HttpPut httpPut = new HttpPut(url);

        if (useHeader) {
            httpPut.addHeader(authorizationHeader(token));

        } else {
            additionalParameter.add(new BasicNameValuePair("access_token", token.getToken()));
        }
        if (!additionalParameter.isEmpty()) {

            httpPut.addHeader("Content-Type", "application/x-www-form-urlencoded");
            try {
                httpPut.setEntity(new UrlEncodedFormEntity(additionalParameter));
            } catch (UnsupportedEncodingException ex) {
                // TODO: invalid url exceptions ????
            }
        }
        return httpPut;
    }

    /**
     * Casts the clients token into a token of the bearer type (if it acutally is one).
     * @param client <code>Client</code> client containing the token
     * @return <code>BearerToken<code> the clients token as a Bearer-Type
     * @throws InvalidTokenTypeException if the token can't be casted
     */
    private BearerToken castToken(Client client)
        throws InvalidTokenTypeException {
        BearerToken token;
        try {
            token = (BearerToken) client.getAccessToken();
        } catch (ClassCastException e) {
            throw new InvalidTokenTypeException("The token used for this request is not a BEARER token");
        }
        if (!client.getAccessToken().getType().equalsIgnoreCase("Bearer")) {
            throw new InvalidTokenTypeException("The token used for this request is not a BEARER token. It is of the type:" + token.getType());
        }
        return token;
    }

    /**
     * returns the http authorization header with the bearer token as authorization
     * @param token <code>Token</code> the token that is to be included in the authorization header
     * @return the http authorization header
     */
    private Header authorizationHeader(Token token) {
        try {
            return new BasicHeader("Authorization", "Bearer " + android.util.Base64.encodeToString(token.getToken().getBytes("UTF-8"), android.util.Base64.NO_WRAP));
        } catch (UnsupportedEncodingException ignored) {
            // UTF-8 character converter is available, exception won't be thrown
            return null;
        }
    }
}
