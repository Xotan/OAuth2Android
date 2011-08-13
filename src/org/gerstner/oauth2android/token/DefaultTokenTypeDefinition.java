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

import java.util.ArrayList;
import java.util.List;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.gerstner.oauth2android.Client;
import org.gerstner.oauth2android.Server;
import org.gerstner.oauth2android.exception.InvalidTokenTypeException;

/**
 * The <code>DefaultTokenTypeDefinition</code> is only used if no other
 * TokenTypeDefinition is created. If this default token type definition is used
 * the <code>Response</code> object will be forced to recognize the correct type
 * of the received tokens.
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 * @see org.gerstner.oauth2android.token.BearerTokenTypeDefinition
 * @see org.gerstner.oauth2android.token.MacTokenTypeDefinition
 */
public class DefaultTokenTypeDefinition extends TokenTypeDefinition{

    @Override
    public String getName() {
        return "default";
    }

    @Override
    public String getHttpAuthenticationScheme() {
        return "";
    }

    @Override
    public List<String> getAdditionalTokenParameters() {
        return new ArrayList<String>();
    }

    @Override
    public String requestProtectedResource(Token token, Client client, Server server, String resourceEndpoint, String body) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Token getEmptyToken() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public HttpGet getAuthorizedHttpGet(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public HttpDelete getAuthorizedHttpDelete(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public HttpPost getAuthorizedHttpPost(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public HttpPut getAuthorizedHttpPut(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}
