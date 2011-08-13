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
 * TokenTypeDefinition serves as a configuration class to define attributes of
 * different kinds of tokens.<br>
 * The OAuth 2.0 protokoll allows to be extended with different types of tokens.
 * two types are implemented: the <italic>bearer</italic> and the <italic>MAC</italic> type.
 * Bearer Tokens are very rudemental and only have most common, basic token attributes as there are:
 * the token String itself, a lifetime and if needed a scope. The MAC Tokens however have a more complex handling.
 * In addition to the basic attributes they hold a <italic>token secret</italic> wich is used in combination
 * with a current timestamp and a randomly generated String to create a signature and sign the messages.
 * Regarding the differences in token implementation this class is used to simplify the definition
 * of different token types 
 *
 * @see BearerToken
 * @see BearerTokenTypeDefinition
 * @see MacToken
 * @see MacTokenTypeDefinition
 * 
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public abstract class TokenTypeDefinition {

    /**
     * The name or identification of the Type of the tokens. It is especially used in the authorization request
     * header field to signal the server the use of this token type.
     * A header could look like this: <br>
     * <code>
     *  Authorization: BEARER jncy789jmsnJl0Dk
     * </code>
     * <br>
     * where <code> BEARER</code> is the name of the token type used for this example
     * @return <code>String</code> this token types name
     */
    public abstract String getName();

    /**
     * Used in the HTTP Authorization Header. For example a bearer token uses
     * <code> Authorization: BEARER </code> to signal the server which token type to expect. MAC token use
     * <code> Authorization: MAC </code> where <code>MAC</code> or <code>BEARER</code> is the name of the HTTP Authentication Scheme.
     * @return String authentication scheme used in the HTTP-Authorization Header
     */
    public abstract String getHttpAuthenticationScheme();

    /**
     * Returns the additional parameters names of this token type
     * @return <code>List<String></code> additional parameter names
     */
    public abstract List<String> getAdditionalTokenParameters();

    /**
     * Constructs the Presentation of the token and the authorization.<br>
     * Where some token types, as the bearer token, only require the token String itself, others like the MAC token type
     * expect more parameters in this header field.<br>
     * When defining a new token type, it is important to know how the token should present the authorization in the
     * request. Either it is within the HTTP-Authorization Header or in the HTTP body itself. A server is supposed to support both
     * but only one should be used at a time.<br><br>
     * <strong>Examples:</strong><br>
     * Bearer-Token (within the HTTP-AUthorization Header):<br><br>
     * <code>
     * Authorization: Bearer 09jk578khs62ldg<br>
     * </code><br>
     * where <code>"Authorization"</code> is the header title, <code>"BEARER"</code> the authentication scheme and <code>"09jk578khs62ldg"</code> (the token string) is the actual Authorization Header Field.<br>
     * <br>
     * MAC-Token (within the HTTP-AUthorization Header):<br>
     * <code>
     * <table border=0>
     * <tr><td><code>Authorization: MAC</code></td><td><code>id</code></td><td> // the token id, e.g. 09jk578khs62ldg</td> </tr>
     * <tr><td></td><td><code>timestamp</code></td><td> // timestamp of the requests creation, e.g. 137131204</td></tr>
     * <tr><td></td><td><code>issuer</code></td><td> // issuer of the token, e.g. tokens.example.com:443</td></tr>
     * <tr><td></td><td><code>nonce</code></td><td> // a random string</td></tr>
     * <tr><td></td><td><code>bodyhash</code></td><td> // the optional request payload body hash</td></tr>
     * <tr><td></td><td><code>mac</code></td><td> // the calculated request mac</td></tr>
     * </table>
     * </code>
     * @param token  containing token specific parameters
     * @param client containing all parameters of the clint
     * @param server
     * @param resourceEndpoint actual url where the request is directed to
     * @return <code>String</code> containing the authorization for the request
     */
    public abstract String requestProtectedResource(Token token, Client client, Server server, String resourceEndpoint, String body);

    /**
     * Returns a new, empty token of the corresponding token type. 
     * @return new Token of the corresponding type to this definition
     */
    public abstract Token getEmptyToken();

    /**
     * To make an authorized request for a protected resource using GET, this method includes all authorization parameters
     * according to the specification of the Access Tokens type.<br>
     * It is possible to include additional (non OAuth) parameters in the request, that will be transformed according to the token type specification.
     * For example parameters pointing to the resources this request targets.<br>
     * The requestURI should point to the requests endpoint, according to the service providers API specification. It does not have to include the complete
     * host URL, since this is already defined in the Server Object.<br>
     * Typically, the authorization gets included in the Authorization Request Header, since some token types don't support other authorization methods.
     * If however, the service provider is not able to accept Authorization Request Headers (wich according to the OAuth specification, he MUST be able to)
     * or the client is not able to manipulate the Request Headers (Android clients should be able to) or if there are other circumstances, the authorization
     * may be included in the uri itself. <br>
     *
     * <code>
     * <p>
     * <b>Example:</b><br>
     * <pre>
     * List myList = new List<NameValuePair>();          // list with additional parameter (could be the resources)
     *      myList.add("a","1");          // example parameter a=1
     *      myList.add("b","4");          // example parameter b=4
     *
     * String requestUri = "/request";    // the whole url would be: www.example.com/request
     * boolean useHeader = true;          // use the http header for authorization
     *
     *  // to request the protected resource using myServer and myClient get the HttpGet object
     * <strong>HttpGet myRequest = getAuthorizedHttpGet( myList, requestUri, myServer, myClient, useHeader );</strong>
     *
     *  // finally to execute the request
     * HttpClient myClient = new HttpDefaultClient();
     * myClient.execute( myRequest );
     * </pre>
     * </p>
     * </code>
     *
     *
     * @param additionalParameter List of additional, non-OAuth parameters, that should be included in the request
     * @param requestUri
     * @param server
     * @param client
     * @param useHeader boolean set true, to use Http Authorization Header, false otherwise
     * @return<code>HttpGet</code> instance to make the request
     */
    public abstract HttpGet getAuthorizedHttpGet(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException;
    /**
     * To make an authorized request for a protected resource using GET, this method includes all authorization parameters
     * according to the specification of the Access Tokens type.<br>
     * It is possible to include additional (non OAuth) parameters in the request, that will be transformed according to the token type specification.
     * For example parameters pointing to the resources this request targets.<br>
     * The requestURI should point to the requests endpoint, according to the service providers API specification. It does not have to include the complete
     * host URL, since this is already defined in the Server Object.<br>
     * Typically, the authorization gets included in the Authorization Request Header, since some token types don't support other authorization methods.
     * If however, the service provider is not able to accept Authorization Request Headers (wich according to the OAuth specification, he MUST be able to)
     * or the client is not able to manipulate the Request Headers (Android clients should be able to) or if there are other circumstances, the authorization
     * may be included in the uri itself. <br>
     *
     * <code>
     * <p>
     * <b>Example:</b><br>
     * <pre>
     * List myList = new List<NameValuePair>();          // list with additional parameter (could be the resources)
     *      myList.add("a","1");          // example parameter a=1
     *      myList.add("b","4");          // example parameter b=4
     *
     * String requestUri = "/request";    // the whole url would be: www.example.com/request
     * boolean useHeader = true;          // use the http header for authorization
     *
     *  // to request the protected resource using myServer and myClient get the HttpGet object
     * <strong>HttpGet myRequest = getAuthorizedHttpGet( myList, requestUri, myServer, myClient, useHeader );</strong>
     *
     *  // finally to execute the request
     * HttpClient myClient = new HttpDefaultClient();
     * myClient.execute( myRequest );
     * </pre>
     * </p>
     * </code>
     *
     *
     * @param additionalParameter List of additional, non-OAuth parameters, that should be included in the request
     * @param requestUri
     * @param server
     * @param client
     * @param useHeader boolean set true, to use Http Authorization Header, false otherwise
     * @return <code>HttpDelete</code> instance to make the request
     */
    public abstract HttpDelete getAuthorizedHttpDelete(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException;

    /**
     * To make an authorized request for a protected resource using POST, this method includes all authorization parameters
     * according to the specification of the Access Tokens type.<br>
     * It is possible to include additional (non OAuth) parameters in the request, that will be transformed according to the token type specification.
     * For example parameters pointing to the resources this request targets.<br>
     * The requestURI should point to the requests endpoint, according to the service providers API specification. It does not have to include the complete
     * host URL, since this is already defined in the Server Object.<br>
     * Typically, the authorization gets included in the Authorization Request Header, since some token types don't support other authorization methods.
     * If however, the service provider is not able to accept Authorization Request Headers (wich according to the OAuth specification, he MUST be able to)
     * or the client is not able to manipulate the Request Headers (Android clients should be able to) or if there are other circumstances, the authorization
     * may be included in the request body. <br>
     *
     * <code>
     * <p>
     * <b>Example:</b><br>
     * <pre>
     * List myList = new List<NameValuePair>();          // list with additional parameter (could be the resources)
     *      myList.add("a","1");          // example parameter a=1
     *      myList.add("b","4");          // example parameter b=4
     *
     * String requestUri = "/request";    // the whole url would be: www.example.com/request
     * boolean useHeader = true;          // use the http header for authorization
     *
     *  // to request the protected resource using myServer and myClient get the HttpGet object
     * <strong>HttpPost myRequest = getAuthorizedHttpGet( myList, requestUri, myServer, myClient, useHeader );</strong>
     *
     *  // finally to execute the request
     * HttpClient myClient = new HttpDefaultClient();
     * myClient.execute( myRequest );
     * </pre>
     * </p>
     * </code>
     *
     *
     * @param additionalParameter List of additional, non-OAuth parameters, that should be included in the request
     * @param requestUri
     * @param server
     * @param client
     * @param useHeader true to use Http Authorization Header, false otherwise
     * @return <code>HttpPost</code> instance to make the request
     */
    public abstract HttpPost getAuthorizedHttpPost(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException;
    /**
     * To make an authorized request for a protected resource using POST, this method includes all authorization parameters
     * according to the specification of the Access Tokens type.<br>
     * It is possible to include additional (non OAuth) parameters in the request, that will be transformed according to the token type specification.
     * For example parameters pointing to the resources this request targets.<br>
     * The requestURI should point to the requests endpoint, according to the service providers API specification. It does not have to include the complete
     * host URL, since this is already defined in the Server Object.<br>
     * Typically, the authorization gets included in the Authorization Request Header, since some token types don't support other authorization methods.
     * If however, the service provider is not able to accept Authorization Request Headers (wich according to the OAuth specification, he MUST be able to)
     * or the client is not able to manipulate the Request Headers (Android clients should be able to) or if there are other circumstances, the authorization
     * may be included in the request body. <br>
     *
     * <code>
     * <p>
     * <b>Example:</b><br>
     * <pre>
     * List myList = new List<NameValuePair>();          // list with additional parameter (could be the resources)
     *      myList.add("a","1");          // example parameter a=1
     *      myList.add("b","4");          // example parameter b=4
     *
     * String requestUri = "/request";    // the whole url would be: www.example.com/request
     * boolean useHeader = true;          // use the http header for authorization
     *
     *  // to request the protected resource using myServer and myClient get the HttpGet object
     * <strong>HttpPost myRequest = getAuthorizedHttpGet( myList, requestUri, myServer, myClient, useHeader );</strong>
     *
     *  // finally to execute the request
     * HttpClient myClient = new HttpDefaultClient();
     * myClient.execute( myRequest );
     * </pre>
     * </p>
     * </code>
     *
     *
     * @param additionalParameter List of additional, non-OAuth parameters, that should be included in the request
     * @param requestUri
     * @param server
     * @param client
     * @param useHeader true to use Http Authorization Header, false otherwise
     * @return <code>HttpPut</code> instance to make the request
     */
    public abstract HttpPut getAuthorizedHttpPut(List<NameValuePair> additionalParameter, String requestUri, Server server, Client client, boolean useHeader)
        throws InvalidTokenTypeException;
}
