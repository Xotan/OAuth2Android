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

import java.util.ArrayList;
import java.util.List;
import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;
import org.gerstner.oauth2android.exception.InvalidClientException;
import org.gerstner.oauth2android.exception.InvalidGrantException;
import org.gerstner.oauth2android.exception.InvalidRequestException;
import org.gerstner.oauth2android.exception.InvalidScopeException;
import org.gerstner.oauth2android.exception.OAuthException;
import org.gerstner.oauth2android.exception.UnauthorizedClientException;
import org.gerstner.oauth2android.exception.UnsupportedGrantTypeException;
import org.json.JSONException;

/**
 *
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class StringParser {

    public static List<NameValuePair> parseForParameters(String stringResponse)
        throws JSONException, InvalidRequestException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException {
        OAuthException exception = null;
        List<NameValuePair> parameterList = new ArrayList<NameValuePair>();
        String[] parameters = stringResponse.split("&");
        for (String parameter : parameters) {
            if (parameter.contains("?")) {
                parameterList.add(new BasicNameValuePair("redirectUri", parameter.split("?")[0]));
                parameter = parameter.split("?")[1];
            }
            if (parameter.contains("=")) {

                String[] pair = parameter.split("=");
                BasicNameValuePair basicNameValuePair = new BasicNameValuePair(pair[0], pair[1]);
                parameterList.add(basicNameValuePair);
                if (basicNameValuePair.getName().equalsIgnoreCase("error")) {
                    exception = ErrorParser.getException(basicNameValuePair.getValue());
                }
            }
        }
        if (exception != null) {
            throw exception;
        }
        return parameterList;
    }
}
