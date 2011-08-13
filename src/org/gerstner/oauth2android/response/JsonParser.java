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

import org.gerstner.oauth2android.exception.InvalidClientException;
import org.gerstner.oauth2android.exception.InvalidGrantException;
import org.gerstner.oauth2android.exception.InvalidRequestException;
import org.gerstner.oauth2android.exception.InvalidScopeException;
import org.gerstner.oauth2android.exception.InvalidTokenTypeException;
import org.gerstner.oauth2android.exception.OAuthException;
import org.gerstner.oauth2android.exception.UnauthorizedClientException;
import org.gerstner.oauth2android.exception.UnsupportedGrantTypeException;
import org.gerstner.oauth2android.token.BearerTokenTypeDefinition;
import org.gerstner.oauth2android.token.DefaultTokenTypeDefinition;
import org.gerstner.oauth2android.token.MacTokenTypeDefinition;
import org.gerstner.oauth2android.token.RefreshToken;
import org.gerstner.oauth2android.token.Token;
import org.gerstner.oauth2android.token.TokenTypeDefinition;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * If the client received an "application/JSON" answer, this class
 * contains the appropriate methods to analyse the <code>JSONObject</code> and
 * search for specific indicators e.g. the access token or an error
 * @see #parseForErrors(org.json.JSONObject)
 * @see #parseForAccessToken(org.json.JSONObject, org.gerstner.oauth2android.token.TokenTypeDefinition)
 * @see #parseForRefreshToken(org.json.JSONObject)
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class JsonParser {

    /**
     * Goes through the JSONObject and looks for error codes. If an error was found
     * the corresponding exception will be created. If the server included a more detailed
     * error description or a url leading to an error webpage the method will include
     * the description or the url into the OAuthException
     * @param jsonObject
     * @throws JSONException
     * @throws InvalidRequestException
     * @throws InvalidClientException
     * @throws InvalidGrantException
     * @throws UnauthorizedClientException
     * @throws UnsupportedGrantTypeException
     * @throws InvalidScopeException
     * @throws OAuthException
     */
    public static void parseForErrors(JSONObject jsonObject)
        throws JSONException, InvalidRequestException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException {
        // at this point there is a 400 error code

        if (jsonObject.has("error")) {
            String error = jsonObject.getString("error");
            String description = "";
            String uri = "";

            if (jsonObject.has("error_description")) {
                description = jsonObject.getString("error_description");
            }
            if (jsonObject.has("error_uri")) {
                uri = jsonObject.getString("error_uri");
            }

            OAuthException exception = ErrorParser.getException(error);

            exception.setError(error);
            exception.setErrorDescription(description);
            exception.setErrorUri(uri);
            throw exception;
        }
    }

    /**
     * Parses the Json retrieved from the Response and searches
     * it for patterns, as for example "access_token" or in the
     * tokenTypeDefinition predefined token attributes. If an access token was
     * found in the resonse, this method will determin the type of the token
     * and wich additional token attributes were used.<br>
     * If no or an empty tokenTypeDefinition was defined, this method 
     * determines the token type by the given parameters from the JSON object.
     * Two types can automatically be detected: <br>
     * <strong> BearerToken, MACToken</strong>
     *
     * @param jsonObject
     * @param tokenTypeDefinition
     * @return the access token if found, or null otherwise
     */
    public static Token parseForAccessToken(JSONObject jsonObject,
                                            TokenTypeDefinition tokenTypeDefinition)
        throws InvalidTokenTypeException {
        Token accessToken = null;

        if (jsonObject.has("access_token")) {
            String accessTokenIdentifier = "";
            try {
                accessTokenIdentifier = jsonObject.getString("access_token");
            } catch (JSONException ex) {
            } // Expires
            Long secondsValid = -1l;
            if (jsonObject.has("expires_in")) {
                try {
                    secondsValid = jsonObject.getLong("expires_in");
                } catch (JSONException ex) {
                }
            }

            if (tokenTypeDefinition instanceof DefaultTokenTypeDefinition) {
                // Token Type
                String tokenType = "";
                if (jsonObject.has("token_type")) {
                    try {
                        tokenType = jsonObject.getString("token_type");
                    } catch (JSONException ex) {
                        throw new InvalidTokenTypeException("Type of the issued"
                            + " token could not be determined.");
                    }
                }
                // MAC Token Type
                if (tokenType.equalsIgnoreCase("mac")) {
                    tokenTypeDefinition = new MacTokenTypeDefinition();
                } // Default / Bearer Token Type
                else if (tokenType.equalsIgnoreCase("bearer")) {
                    tokenTypeDefinition = new BearerTokenTypeDefinition();
                } else {
                    throw new InvalidTokenTypeException("Type of the issued "
                        + "token has an unknown format: " + tokenType);
                }
            }
            accessToken = tokenTypeDefinition.getEmptyToken();
            accessToken.setToken(accessTokenIdentifier);
            accessToken.setSecondsValid(secondsValid);
            for (String attribute : tokenTypeDefinition.getAdditionalTokenParameters()) {
                if (jsonObject.has(attribute)) {
                    try {
                        accessToken.addAdditionalParameter(attribute, jsonObject.getString(attribute));
                    } catch (JSONException ex) {
                        accessToken.addAdditionalParameter(attribute, "");
                    }
                }
            }
        }
        return accessToken;
    }

    /**
     * Parses the JSONObject for the refresh token and returns it, if no refresh token
     * was found <code>null</code> is returned.
     *
     * @param jsonObject <code>JSONObject</code> that was included in the response
     * @return a <code>token</code> containing the refresh token if one was issued, <code>null</code> otherwise
     */
    public static Token parseForRefreshToken(JSONObject jsonObject) {
        Token refreshToken = null;
        try {
            refreshToken = new RefreshToken(jsonObject.getString("refresh_token"));
        } catch (JSONException ex) {
        }
        return refreshToken;
    }
}
