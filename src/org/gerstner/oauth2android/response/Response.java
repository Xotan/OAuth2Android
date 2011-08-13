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
package org.gerstner.oauth2android.response;

import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.StatusLine;
import org.apache.http.util.EntityUtils;
import org.gerstner.oauth2android.exception.*;
import org.gerstner.oauth2android.token.Token;
import org.gerstner.oauth2android.token.TokenTypeDefinition;
import org.json.JSONException;
import org.json.JSONObject;

/**
 *
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class Response {

    private int statusCode;
    private String requestUrl;
    private String stringResponse;
    private JSONObject jsonResponse;
    private List<NameValuePair> parameterList;
    private HttpResponse httpResponse;
    private Token accessToken;
    private Token refreshToken;
    private static final String TAG = "OAUTH - Response";

    public Response(HttpResponse httpResponse)
        throws IOException, InvalidRequestException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException {
        this.httpResponse = httpResponse;
        try {
            initialAnalysis();
        } catch (JSONException ex) {
            // TODO : JSON EXCEPTION What todo?
        }
    }

    private boolean initialAnalysis()
        throws JSONException, InvalidRequestException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException {

        StatusLine statusLine = this.httpResponse.getStatusLine();
        this.statusCode = statusLine.getStatusCode();
        try {
            getStringEntity();
        } catch (IOException ex) {
            Logger.getLogger(Response.class.getName()).log(Level.SEVERE, null, ex);
        }

        if (parseStringEntityForJson()) {
            JsonParser.parseForErrors(jsonResponse);
        } else if (parseStringEntityForParameters()) {
        }

        switch (statusCode) {
            case (200): {
                return true;
            }
            case (401): {
                OAuthException unauthorizedClientException = new UnauthorizedClientException(statusLine.getReasonPhrase());
                unauthorizedClientException.setErrorDescription(this.httpResponse.getFirstHeader("WWW-Authenticate").getValue());
                return false;
            }
        }
        return true;
    }

    public void parseForTokens(TokenTypeDefinition tokenTypeDefinition) throws InvalidTokenTypeException {
        this.accessToken = JsonParser.parseForAccessToken(jsonResponse, tokenTypeDefinition);
        this.refreshToken = JsonParser.parseForRefreshToken(jsonResponse);
    }

    private void getStringEntity()
        throws IOException {
        HttpEntity entity = httpResponse.getEntity();
        this.stringResponse = EntityUtils.toString(entity, EntityUtils.getContentCharSet(entity));
    }

    private boolean parseStringEntityForJson() {
        if (httpResponse.getFirstHeader("Content-Type").getValue().equalsIgnoreCase("application/json")) {
            if (stringResponse != null && !stringResponse.isEmpty()) {
                try {
                    jsonResponse = new JSONObject(stringResponse);
                } catch (JSONException ex) {
                    return false;
                }
                return true;
            }
        }
        return false;
    }

    private boolean parseStringEntityForParameters()
        throws JSONException, InvalidRequestException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException {
        if (httpResponse.getFirstHeader("Content-Type").getValue().equalsIgnoreCase("application/x-www-form-urlencoded")) {
            if (stringResponse != null && !stringResponse.isEmpty()) {
                this.parameterList = StringParser.parseForParameters(stringResponse);
            }
        }
        return this.parameterList != null;
    }

    private void analyseJsonError() {
    }

    public Token getAccessToken() {
        return this.accessToken;
    }

    public String getTokenType()
        throws NullPointerException {
        if (accessToken == null || accessToken.getType() == null) {
            throw new NullPointerException("No AccessToken available to determine the token type");
        }
        return this.accessToken.getType();
    }

    public Token getRefreshToken() {
        return this.refreshToken;
    }

    public void setRequestUrl(String url) {
        this.requestUrl = url;
    }

    public String getResponseString() {
        return this.stringResponse;
    }

    public boolean hasAccessToken() {
        return this.accessToken != null && this.accessToken.getToken() != null && !this.accessToken.getToken().isEmpty();
    }

    public boolean hasRefreshToken() {
        return this.refreshToken != null && this.refreshToken.getToken() != null && !this.refreshToken.getToken().isEmpty();
    }
}
