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
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.http.Header;
import org.apache.http.NameValuePair;
import org.apache.http.ParseException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpDelete;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.message.BasicHeader;
import org.apache.http.util.EntityUtils;
import org.gerstner.oauth2android.Client;
import org.gerstner.oauth2android.Server;
import org.gerstner.oauth2android.common.Connection;
import org.gerstner.oauth2android.common.Util;
import org.gerstner.oauth2android.exception.InvalidTokenTypeException;

/**
 * The <code>MacTokenTypeDefinition</code>  serves as the configuration class to define attributes of
 * MacTokens.<br>
 * The OAuth 2.0 protokoll allows to be extended with different types of tokens.
 * The MAC Tokens have a more complex handling than the standard bearer token.
 * In addition to the basic attributes they hold a <italic>token secret</italic> wich is used in combination
 * with a current timestamp and a randomly generated String to create a signature and sign the messages.
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 *  @see org.gerstner.oauth2android.token.BearerTokenTypeDefinition
 */
public class MacTokenTypeDefinition
    extends TokenTypeDefinition {

    private final String TAG = "TokenTypeDef";
    private static final int NONCE_LENGTH = 15;

    @Override
    public Token getEmptyToken() {
        return new MacToken();
    }

    @Override
    public String getName() {
        return "mac";
    }

    @Override
    public String getHttpAuthenticationScheme() {
        return "MAC";
    }

    @Override
    public String requestProtectedResource(Token token, Client client, Server server, String resourceEndpoint, String body) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * This method returns a String containing the complete requests signature.<br>
     * You might not need to call this method directly from your application.
     * But if you don't want to use {@link org.gerstner.oauth2android.OAuth#executeProtectedResourceRequest(java.lang.String, java.util.List)}
     * (wich is actually calling this method indirectly to sign the request),
     * you can call {@link #getAuthorizedHttpPost(java.util.List, java.lang.String, org.gerstner.oauth2android.Server, org.gerstner.oauth2android.Client, boolean)}
     * or similar to get a complete, signed request.
     *<br>
     * <br>
     * Here is an example on how the return string might look like (the example is from the
     * draft-ietf-oauth-v2-http-mac-00) (line breaks are for displaying purposes only):
     * <pre>
     * <code>
     *  MAC id="jd93dh9dh39D"
     *      nonce="273156:di3hvdf8",
     *      bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=",
     *      mac="W7bdMZbv9UWOTadASIQHagZyirA="
     * </code>
     * </pre>
     * @param client <code>Client</code> of this application
     * @param server <code>Server</code> for this application
     * @param requestUri <code>String</code> containing this requests endpoint
     * @param requestMethod <code>String</code> value of the http method used (GET, POST)
     * @param ext <code>String</code> value of the extension parameters
     * @param body <code>String</code> representation of the complete requests body
     * @return <code>String</code> with complete signature
     * @throws InvalidTokenTypeException thrown if the token is not of the mac type or containes incorrect mac credentials
     */
    public String constructAuthorization(Client client, Server server, String requestUri, String requestMethod, String ext, String body)
        throws InvalidTokenTypeException {
        MacToken macToken = castToken(client);
        String nonce = System.currentTimeMillis() - macToken.getCreated() + ":" + Util.getRandomString(NONCE_LENGTH);
        String bodyhash = calculateBodyHash(body, getHashAlgorithm(macToken.getAdditionalParameters().get("algorithm")));
        ext = (ext == null) ? "" : ext;
        String host = server.getResourceServer().split("://")[1];
        String port = server.getResourceServer().split("://")[0];
        if (port.equalsIgnoreCase("http")) {
            port = "80";
        } else if (port.equalsIgnoreCase("https")) {
            port = "443";
        }

        String normalizedString = constructNormalizedString(nonce, requestMethod, requestUri, host, port, bodyhash, ext);
        String mac = calculateMAC(macToken.getAdditionalParameters().get("secret"), normalizedString, getMACAlgorithm(macToken.getAdditionalParameters().get("algorithm")));
        return constructAuthorizationHeaderField(macToken.getToken(), nonce, bodyhash, ext, mac);

    }

    /**
     * This method constructs the normalized string wich is used to calculate the
     * mac for the request. To get a valid mac it might be neccessary to calculate
     * the bodyhash for the request first. See {@link #calculateBodyHash(java.lang.String, java.lang.String) }<br>
     * The resulting normalized string might look similar to this (example taken from the draft-ietf-oauth-v2-http-mac-00):<br>
     * <pre>
     * <code>
     *  273156:di3hvdf8\n
     *   POST\n
     *   /request\n
     *   example.net
     *   80\n
     *   k9kbtCIy0CkI3/FEfpS/oIDjk6k=\n
     *   \n
     * </code>
     * </pre>
     *
     * @param nonce <code>String</code> containing the tokens age and a random string (e.g.  "273156:di3hvdf8")
     * @param requestMethod <code>String</code> value of the http method (e.g. "POST")
     * @param requestUri <code>String</code> of the requests uri (e.g. "/request")
     * @param requestHost <code>String</code> representation of the hosts uri as contained in the requests header (e.g. "example.net")
     * @param requestPort <code>String</code> the requests port (e.g. "80" for http or "443" for https)
     * @param bodyhash <code>String</code> the previously calculated bodyhash (remember even an empty body produces a bodyhash)
     * @param ext <code>String</code> some extension parameters for the request
     * @return <code>String</code> of the complete normalized String
     */
    private String constructNormalizedString(String nonce, String requestMethod, String requestUri, String requestHost, String requestPort, String bodyhash, String ext) {
        String newline = "\n";
        String normalizedString = nonce + newline
                                  + requestMethod.toUpperCase() + newline
                                  + requestUri + newline
                                  + requestHost + newline // request Header
                                  + requestPort + newline // wie im request Header
                                  + bodyhash + newline
                                  + ext + newline;                     // ext Header ... ????
        return normalizedString;
    }

    /**
     * This method constructs the actual http authorization header field with the signature.<br>
     * All included parameters need to be calculated first. <br>
     * Here is an example on how the return string might look like (the example is from the
     * draft-ietf-oauth-v2-http-mac-00) (line breaks are for displaying purposes only):
     * <pre>
     * <code>
     *  MAC id="jd93dh9dh39D"
     *      nonce="273156:di3hvdf8",
     *      bodyhash="k9kbtCIy0CkI3/FEfpS/oIDjk6k=",
     *      mac="W7bdMZbv9UWOTadASIQHagZyirA="
     * </code>
     * </pre>
     * @param macKeyIdentifier <code>String </code> the token identifier
     * @param nonce <code>String</code> containing the tokens age and a random string (e.g.  "273156:di3hvdf8")
     * @param bodyhash <code>String </code> the requests bodyhash. See {@link #calculateBodyHash(java.lang.String, java.lang.String)}
     * @param ext <code>String</code> some extension parameters for the request
     * @param mac <code>String</code> the calculated mac. See {@link #calculateMAC(java.lang.String, java.lang.String, java.lang.String)}
     * @return <code>String</code> with the authorized header field value
     *
     * @see #constructAuthorization(org.gerstner.oauth2android.Client, org.gerstner.oauth2android.Server, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
     */
    private String constructAuthorizationHeaderField(String macKeyIdentifier, String nonce, String bodyhash, String ext, String mac) {
        String authorizationHeaderField = this.getHttpAuthenticationScheme() + " ";
        authorizationHeaderField += "id=\"" + macKeyIdentifier + "\","
                                    + "nonce=\"" + nonce + "\","
                                    + ((!bodyhash.equalsIgnoreCase("")) ? "bodyhash=\"" + bodyhash + "\"," : "")
                                    + ((!ext.equalsIgnoreCase("")) ? "ext=\"" + ext + "\"," : "")
                                    + "mac=\"" + mac + "\"";

        return authorizationHeaderField;
    }

    /**
     * Seperates the Hash algorithm (sha-1 or sha-256) from the hmac algorithm string.<br>
     * e.g "hmac-sha-1" produces "sha-1"<br>
     * @param algorithm
     * @return
     */
    private String getHashAlgorithm(String algorithm) {
        return algorithm.substring(algorithm.indexOf("sha", 0));
    }

    /**
     * Constructs a java readable algorithm designation.<br>
     * e.g. "hmac-sha-1" produces "hmacsha1".
     * @param algorithm
     * @return <code>String</code> of the algorithms name
     */
    private static String getMACAlgorithm(String algorithm) {
        return algorithm.replace("-", "").toUpperCase();
    }

    private String calculateBodyHash(String body, String algorithm)
        throws InvalidTokenTypeException {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            String bodyhash = Base64.encodeToString(md.digest(body.getBytes()), Base64.DEFAULT);
            return bodyhash;
        } catch (NoSuchAlgorithmException ex) {
            throw new InvalidTokenTypeException("This token contains no or an invalid algorithm to calculate the bodyhash");
        }
    }

    private static String calculateMAC(String key, String normalizedString, String algorithm) {
        String macString = "";
        try {
            System.out.println("algorithm=" + algorithm);
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key.getBytes(), algorithm));
            macString = Base64.encodeToString(mac.doFinal(normalizedString.getBytes()), Base64.DEFAULT);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MacTokenTypeDefinition.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MacTokenTypeDefinition.class.getName()).log(Level.SEVERE, null, ex);
        }
        return macString;
    }

    @Override
    public List<String> getAdditionalTokenParameters() {
        List<String> tokenAttributes = new ArrayList<String>(1);
        tokenAttributes.add("secret");
        tokenAttributes.add("algorithm");
        return tokenAttributes;
    }

    @Override
    public HttpGet getAuthorizedHttpGet(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException {
        String ext = castToken(client).getExt();

        String url = server.getResourceServer() + (requestUri.startsWith("/") ? requestUri : "/" + requestUri);
        if (additionalParameter != null && !additionalParameter.isEmpty()) {
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

        HttpGet httpGet = new HttpGet(url);
        Header header = new BasicHeader("Authorization", constructAuthorization(client, server, httpGet.getRequestLine().getUri(), Connection.HTTP_METHOD_GET, ext, ""));
        httpGet.addHeader(header);
        return httpGet;
    }

    @Override
    public HttpDelete getAuthorizedHttpDelete(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException {
      String ext = castToken(client).getExt();

        String url = server.getResourceServer() + (requestUri.startsWith("/") ? requestUri : "/" + requestUri);
        if (additionalParameter != null && !additionalParameter.isEmpty()) {
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

        HttpDelete httpDelete = new HttpDelete(url);
        Header header = new BasicHeader("Authorization", constructAuthorization(client, server, httpDelete.getRequestLine().getUri(), Connection.HTTP_METHOD_DELETE, ext, ""));
        httpDelete.addHeader(header);
        return httpDelete;
    }

    @Override
    public HttpPost getAuthorizedHttpPost(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException {
        String ext = castToken(client).getExt();
        String url = server.getResourceServer() + (requestUri.startsWith("/") ? requestUri : "/" + requestUri);
        HttpPost httpPost = new HttpPost(url);
        String body = "";
        if (additionalParameter != null && !additionalParameter.isEmpty()) {
            httpPost.addHeader("Content-Type", "application/x-www-form-urlencoded");
            try {
                httpPost.setEntity(new UrlEncodedFormEntity(additionalParameter));
                try {
                    body = EntityUtils.toString(httpPost.getEntity());
                } catch (IOException ex) {
                    Logger.getLogger(MacTokenTypeDefinition.class.getName()).log(Level.SEVERE, null, ex);
                } catch (ParseException ex) {
                    Logger.getLogger(MacTokenTypeDefinition.class.getName()).log(Level.SEVERE, null, ex);
                }
            } catch (UnsupportedEncodingException ignored) {
            }
        }
        Header header = new BasicHeader("Authorization", constructAuthorization(client, server, httpPost.getRequestLine().getUri(), Connection.HTTP_METHOD_POST, ext, body));
        httpPost.addHeader(header);

        return httpPost;
    }

    @Override
    public HttpPut getAuthorizedHttpPut(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException {
        String ext = castToken(client).getExt();
        String url = server.getResourceServer() + (requestUri.startsWith("/") ? requestUri : "/" + requestUri);
        HttpPut httpPut = new HttpPut(url);
        String body = "";
        if (additionalParameter != null && !additionalParameter.isEmpty()) {
            httpPut.addHeader("Content-Type", "application/x-www-form-urlencoded");
            try {

                httpPut.setEntity(new UrlEncodedFormEntity(additionalParameter));
                try {
                    body = EntityUtils.toString(httpPut.getEntity());
                } catch (IOException ex) {
                    Logger.getLogger(MacTokenTypeDefinition.class.getName()).log(Level.SEVERE, null, ex);
                } catch (ParseException ex) {
                    Logger.getLogger(MacTokenTypeDefinition.class.getName()).log(Level.SEVERE, null, ex);
                }
            } catch (UnsupportedEncodingException ex) {
                // TODO: invalid url exceptions ????
            }
        }
        Header header = new BasicHeader("Authorization", constructAuthorization(client, server, httpPut.getRequestLine().getUri(), Connection.HTTP_METHOD_PUT, ext, body));
        httpPut.addHeader(header);

        return httpPut;
    }

    /**
     * Casts the clients token into a token of the mac type (if it acutally is one).
     * @param client <code>Client</code> client containing the token
     * @return <code>MacToken<code> the clients token as a Mac-Type
     * @throws InvalidTokenTypeException if the token can't be casted
     */
    private MacToken castToken(Client client)
        throws InvalidTokenTypeException {
        MacToken token;
        try {
            token = (MacToken) client.getAccessToken();
        } catch (ClassCastException e) {
            throw new InvalidTokenTypeException("The token used for this request is not a MAC token");
        }
        if (!client.getAccessToken().getType().equalsIgnoreCase("Mac")) {
            throw new InvalidTokenTypeException("The token used for this request is not a MAC token. It is of the type:" + token.getType());
        }
        return token;
    }
}
