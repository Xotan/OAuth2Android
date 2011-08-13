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
package org.gerstner.oauth2android;

import org.gerstner.oauth2android.response.Response;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.gerstner.oauth2android.common.Connection;
import org.gerstner.oauth2android.exception.*;
import org.gerstner.oauth2android.token.DefaultTokenTypeDefinition;
import org.gerstner.oauth2android.token.RefreshToken;
import org.gerstner.oauth2android.token.Token;
import org.gerstner.oauth2android.token.TokenTypeDefinition;

/**
 * The OAuth Object is the "control center" for all steps within the OAuth-flow.
 * The client application only needs one instance of this class to be able to make
 * all OAuth related requests. <br>
 * To be able to make all requests it is essential to initialize the OAuth object
 * completely. After initialization all requests can be made as described in the
 * service providers API<br>
 * See the examples below to get a basic understanding on the OAuth flow and how to
 * use the OAuth-Object<br>
 * <pre>
 * <b>Example flow</b>
 *
 * <code>
 * OAuth myOAuth = new OAuth( {@link org.gerstner.oauth2android.Server} myServer, {@link org.gerstner.oauth2android.Client} myClient, {@link org.gerstner.oauth2android.token.TokenTypeDefinition} tokenType );
 *  myOAuth.returnAuthorizationRequestUri();                     // call this website with a browser to get the authorization
 *  myOAuth.executeAccessTokenRequest( "authorizationCode" );    // code from the website
 *  myOAuth.executeProtectedResourceRequest( {@link org.gerstner.oauth2android.Server#resourceServer} url, parameterList );
 * </code>
 *
 * <b>Detailed Example</b>

 * <i>The server has the following API endpoints (read your service providers
 * documentation for more information):</i>
 *
 *   authorization server: "https://login.example.com"
 *   resource server: "https://www.example.com/resources"
 *
 * <i>The service provider issues the following client credentials (after
 * registering the application):</i>
 *
 *   client id = "abc"
 *   client secret = "def"
 *
 * <i>To be read in the service providers documentation:
 *  - for authorization from the resource owner the provider issues an AUTHORIZATION CODE
 *  - for authorizing towards the provider the server expects a BEARER Token
 *  - the redirection uri for applications: oob</i>
 *
 * <i>Instantiation of the OAuth object:</i>
 *
 * <code>
 * Server myServer = new Server(<i>"https://login.example.com", "https://login.example.com", "https://www.example.com"</i>);
 *  Client myClient = new Client(<i>"abc", "def", "oob"</i>);
 *  OAuth myOAuth   = new OAuth( myServer, myClient, new BearerTokenTypeDefinition() );
 * </code>
 *
 * <i>How to get the authorization from the resource owner:</i>
 *
 * <code>
 * String uri = myOAuth.returnAuthorizationRequestUri();
 * </code>
 * <i>call this uri with an external user agend (web browser) and get the authorization code. </i>
 * <i>Then request the access token:</i>
 * <code>
 * String authorizationCode = "xyz";
 * myOAuth.executeAccessTokenRequest( authorizationCode );
 * </code>
 * <i>the uri where the specific resources are:
 * "https://www.example.com/resources/me/myPhotos"
 *
 * the part needed: "/me/myPhotos"
 *
 * the parameters needed for the request:
 * photo="1.jpg"
 * action="delete"
 *
 * prepare the list of parameters:</i>
 *
 * <code>
 * List&lt;NameValuePair&gt; parameterList = new ArrayList&lt;NameValuePair&gt;();
 *  parameterList.add( new BasicNameValuePair( <i>"photo","1.jpg"</i> ));
 *  parameterList.add( new BasicNameValuePair( <i>"action","delete"</i> ));
 * </code>
 * <i>the actual request:</i>
 * <code>
 * myOAuth.executeProtectedResourceRequest( <i>"/me/myPhotos"</i>, parameterList );
 * </code>
 * </pre>
 *
 * @see org.gerstner.oauth2android.Server
 * @see org.gerstner.oauth2android.Client
 * @see org.gerstner.oauth2android.token.TokenTypeDefinition
 *
 * @author Christoph Gerstner <development@christoph-gerstner.de>
 */
public class OAuth {

    /**
     * The scope is an array of Strings containing all scopes of the access request.
     * The scope describes the access range of a request.
     * The value is defined by the authorization server (see the service providers API documentation
     * for more details). There can be only one value for the scope or multiple, the order is not
     * relevant.
     */
    private String[] scope;
    /**
     * The server contains all URLs and additional informations on the service providers servers.
     * See the service providers documentation for more details.
     */
    private Server server;
    /**
     * The client contains all informations on the client application as for example the client id
     * or the access tokens.
     * See the service providers documentation for more details.
     */
    private Client client;
    /**
     * Opaque value used by the client to maintain state between the request an callback.
     */
    private String state;
    /**
     * Definition of the token type issued by the authorization server. Tokens can have different
     * kinds of types, as there are two that are supported by this library: BEARER and MAC.
     * Since the type of the token defines the tokens parameters and how to use them, the <code>TokenTypeDefinition</code>
     * provides the methods to handle the different kinds of tokens.
     * @see org.gerstner.oauth2android.token.BearerTokenTypeDefinition
     * @see org.gerstner.oauth2android.token.MacTokenTypeDefinition
     *
     */
    private TokenTypeDefinition tokenTypeDefinition;
    /**
     * Flag indicating which character the service provider uses to divide the single scopes
     * in the request. OAuth2.0 defines in its specifications that the whitespace character ought to be used.
     * However it might happen that some service providers expect a different character. By default this
     * flag is set to whitespace;
     */
    private char scopeDivider;

    /**
     * Constructs an OAuth-Object that handles the OAuth specific authorization process
     * for all outgoing an incoming communications. Each OAuth-Object handles one Client
     * and one service provider (Server) the Client connects to. <br>
     *
     * @param server URLs and configurations of the service provider
     * @param client application specific configurations given by the service provider
     * @param tokenTypeDefinition the type of tokens a service provider uses (e.g. Bearer, MAC)
     * @see Client
     * @see Server
     * @see TokenTypeDefinition
     */
    public OAuth(Server server, Client client, TokenTypeDefinition tokenTypeDefinition) {
        this.server = server;
        this.client = client;
        if (tokenTypeDefinition == null) {
            this.tokenTypeDefinition = new DefaultTokenTypeDefinition();
        } else {
            this.tokenTypeDefinition = tokenTypeDefinition;
        }
        this.scopeDivider = ' ';
    }

    /**
     * Returns the Client registered to the current OAuth-Object, with its preset client configuration.
     * @return Client containing the access token
     */
    public Client getClient() {
        return client;
    }

    /**
     * Registers a Client to the current OAuth-Object. The Client is an object containing necessary informations
     * given by the provider about the application as for example the registered client_id or application_id.<br>
     * Contact the service provider for more information.
     * @param client
     */
    public void setClient(Client client) {
        this.client = client;
    }

    /**
     *  Returns the Server registered to the current OAuth-Object, with its preset server configuration.
     * @return <code>Server</code> Instance of the server
     */
    public Server getServer() {
        return server;
    }

    /**
     * Registers a Server to the current OAuth-Object. The Server is an object containing necessary informations
     * given by the provider about the provider itself and its endpoints as for example the authorization endpoint<br>
     * Contact the service provider for more information.
     * @param server
     */
    public void setServer(Server server) {
        this.server = server;
    }

    /**
     * Returns the state if any or an empty string otherwise
     * @return String state
     */
    public String getState() {
        if (this.state != null && !this.state.isEmpty()) {
            return state;
        } else {
            return "";
        }
    }

    /**
     * Sets the state (if necessary)
     * @param state <code>string</code> value of the state
     */
    public void setState(String state) {
        this.state = state;
    }

    /**
     * Returns an <code>array</code> of <code>Strings</code> containing all
     * scopes the access token is valid for.
     * @return <code>String[]</code> of scopes for the access
     */
    public String[] getScope() {
        return scope;
    }

    /**
     * Returns a single string containing all strings of the scope array, divided
     * by a whitespace or a similar scope divider ({@link #scopeDivider}). This method is especially useful when sending the scope in a request
     * to the provider.
     * @return String containing all scopes
     */
    private String getScopeString() {
        String scopeString = "";
        for (int i = 0; i < scope.length - 1; i++) {
            scopeString += scope[i] + scopeDivider;
        }
        scopeString += scope[scope.length - 1];
        return scopeString;
    }

    /**
     * Sets a scope for the intended request an the requested AccessToken for this request.
     * The scope describes what resources the application may access. For more information see
     * the specifications of the service provider.<br>
     * In general a scope is an array of strings, where each string describes one scope "area".
     * To add only one single scope string one can use <code> addScope(String);</code><br>
     * This method overrides all existing scopes set before.
     * @param scope String[] of single scope Strings
     */
    public void setScope(String[] scope) {
        this.scope = scope;
    }

    /**
     * Adds a scope to the intended request an the requested AccessToken for this request.
     * The scope describes what resources the application may access. For more information see
     * the specifications of the service provider.<br>
     * In general a scope is an array of strings, where each string describes one scope "area".
     * To set all scope strings at ones one can use <code> setScope(String[]);</code>
     * If no scope was set before and the scope array is empty a new array is created. Otherwise
     * this single scope String is added to the end of that array.
     * @param scope a single scope String
     */
    public void addScope(String scope) {
        String[] newScope;
        if (this.scope == null || this.scope.length == 0) {
            newScope = new String[1];

        } else {
            newScope = new String[this.scope.length + 1];
        }
        int i = 0;
        while (i < this.scope.length) {
            newScope[i] = this.scope[i++];
        }
        newScope[i] = scope;
        this.scope = newScope;
    }

    /**
     * Returns the character used to divide the scopes. The default setting for this
     * flag is whitespace.
     * @see #scopeDivider
     * @return <code>char</code> used to divide the scopes
     */
    public char getScopeDivider() {
        return scopeDivider;
    }

    /**
     * Sets the character that should be used to divide the scopes. The default setting for this
     * flag is whitespace.
     * @param scopeDivider <code>char</code> that divides two scopes
     * @see #scopeDivider
     */
    public void setScopeDivider(char scopeDivider) {
        this.scopeDivider = scopeDivider;
    }

    /**
     * Returns the instance of the <code>TokenTypeDefinition</code>.
     * @return <code>TokenTypeDefinition</code> defining which token type to use
     */
    public TokenTypeDefinition getTokenTypeDefinition() {
        return tokenTypeDefinition;
    }

    /**
     * Sets the <code>TokenTypeDefinition</code>, defining which token type to use.
     * @param tokenTypeDefinition e.g.<code>BearerTokenTypeDefinition</code>
     * @see org.gerstner.oauth2android.token.BearerTokenTypeDefinition
     * @see org.gerstner.oauth2android.token.MacTokenTypeDefinition
     *
     */
    public void setTokenTypeDefinition(TokenTypeDefinition tokenTypeDefinition) {
        this.tokenTypeDefinition = tokenTypeDefinition;
    }

    /******************************************************************
     ******************** AUTHORIZATION REQUEST ***********************
     ******************************************************************/
    /**
     * Prepares the authorization request with the previously specified parameters
     * in an appropriate way for a http request to get an authorization code considering the OAuth 2.0 specification.
     *
     * @return List<NameValuePair> prepared list of parameters
     */
    private List<NameValuePair> prepareAuthorizationRequest() {
        List<NameValuePair> parameter = new ArrayList<NameValuePair>(3);

        // parameter to signal the server an authorization by code is prefered
        parameter.add(new BasicNameValuePair("response_type", "code"));

        // parameter that are required to identify the client
        parameter.add(new BasicNameValuePair("client_id", client.getClientID()));
        parameter.add(new BasicNameValuePair("redirect_uri", client.getRedirectUri()));

        if (scope != null && scope.length > 0) {
            parameter.add(new BasicNameValuePair("scope", this.getScopeString()));
        }
        if (state != null && !state.isEmpty()) {
            parameter.add(new BasicNameValuePair("state", state));
        }
        return parameter;
    }

    /**
     * Returns a url including all parameters needed to ask the authorization server
     * for the resource owners grant. Direct this url to a user agent capable of
     * displaying web sites in a human readable manner.
     * @return <code>S
     * string</code> representation of the url to pass to a web browser.
     */
    public String returnAuthorizationRequestUri() {
        List<NameValuePair> parameter = prepareAuthorizationRequest();
        String requestUri = this.server.getAuthorizationServer() + "?";

        for (int i = 0; i < parameter.size(); i++) {
            NameValuePair nameValuePair = parameter.get(i);
            requestUri += nameValuePair.getName() + "=" + nameValuePair.getValue() + ((i == parameter.size() - 1) ? "" : "&");
        }
        return requestUri;
    }

    /******************************************************************
     ********************* ACCESS TOKEN REQUEST ***********************
     ******************************************************************/
    /**
     * Prepares the request for an Access-Token by filling the parameters list with
     * the needed parameters, e.g the client_id or grant_type.<br>
     * It can be used for all authorization methods.
     * @return List of NameValuePairs containing the parameters for the request.
     * @see #executeAccessTokenRequest()
     * @see #executeAccessTokenRequest(java.util.List)
     * @see #executeAccessTokenRequest(java.lang.String)
     * @see #executeAccessTokenRequest(java.lang.String, java.util.List)
     * @see #executeAccessTokenRequest(java.lang.String, java.lang.String)
     * @see #executeAccessTokenRequest(java.lang.String, java.lang.String, java.util.List)
     *
     */
    private List<NameValuePair> prepareAccessTokenRequest() {

        List<NameValuePair> parameter = new ArrayList<NameValuePair>(3);
        parameter.add(new BasicNameValuePair("client_id", client.getClientID()));
        parameter.add(new BasicNameValuePair("client_secret", client.getClientSecret()));
        parameter.add(new BasicNameValuePair("redirect_uri", client.getRedirectUri()));
        return parameter;
    }

    /**
     * Finds the access token and the refresh token (if any) in the <code>Response</code> returned by the request.
     * This method is called by any <code>executeAccessTokenRequest</code>. Since this method handles a <code>Response</code> Instance
     * an OAuth specific exception might be thrown if the request is invalid or has errors of any kind.<br>
     * To catch all <code>Exceptions</code> at once, catch {@link org.gerstner.oauth2android.exception.OAuthException}, otherwise
     * a concrete error handling is possible by catching single exceptions.
     * @param parameter all parameters for the request included in a <code>List</code>
     * @return <code>Response</code> instance for further use
     * 
     * @throws InvalidRequestException the request is missing a parameter or is otherwise invalid
     * @throws InvalidTokenTypeException the server did not specify which token type to expect or the wrong token type was received.
     * @throws InvalidClientException the client could not be identified
     * @throws InvalidGrantException the authorization grant is not valid
     * @throws UnauthorizedClientException the token is not valid or is of the wrong type
     * @throws UnsupportedGrantTypeException the client used an unsupported method for the authorization grant
     * @throws InvalidScopeException the scope is incomplete or invalid
     * @throws OAuthException parent class of all OAuth specific exceptions above
     * @throws IOException a connection error occurred during the request
     *
     * @see #executeAccessTokenRequest()
     * @see org.gerstner.oauth2android.response.ErrorParser
     */
    private Response getTokens(List<NameValuePair> parameter)
        throws InvalidRequestException, InvalidTokenTypeException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException, IOException {

        Response response = Connection.httpPostRequest(parameter, this.server.getAccessTokenServer());
        response.parseForTokens(tokenTypeDefinition);
        if (response.hasAccessToken()) {
            Token accessToken = response.getAccessToken();
            accessToken.setScope(this.getScopeString());
            this.client.setAccessToken(accessToken);
        }
        if (response.hasRefreshToken()) {
            this.client.setRefreshToken(response.getRefreshToken());
        }
        return response;
    }

    /**
     * Executes the Request for an Access-Token by transmitting the <b>client credentials</b> only. This method is used
     * only under specific circumstances e.g. when the client is the actual resource owner of the resources he
     * wants to access with the requested access token. 
     * The access token and the refresh token (if any) are automatically assigned to the client instance.
     * See the OAuth 2.0 specification for more details.<br>
     * Under <i>normal</i> circumstances one might call the {@link #executeAccessTokenRequest(java.lang.String)} method.
     * <br><br>
     * Other methods are:
     * <ul>
     * <li>{@link #executeAccessTokenRequest(java.util.List)}  -  transmitting only the <b>client credentials</b> but with a <code>List</code> of additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String)} - used under <i>normal</i> circumstances to get an access token with the <b>authorization code</b></li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.util.List)} - also to transmit the <b>authorization code</b> but with additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.lang.String)} - used to transmit the users <b>password credentials</b> directly</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.lang.String, java.util.List)} - also to transmit the users <b>password credentials</b> directly but with additional parameters</li>
     * </ul>
     *
     * @return Response containing the AccessToken or an error message from the server.
     * @throws InvalidRequestException the request is missing a parameter or is otherwise invalid
     * @throws InvalidTokenTypeException the server did not specify which token type to expect or the wrong token type was received.
     * @throws InvalidClientException the client could not be identified
     * @throws InvalidGrantException the authorization grant is not valid
     * @throws UnauthorizedClientException the token is not valid or is of the wrong type
     * @throws UnsupportedGrantTypeException the client used an unsupported method for the authorization grant
     * @throws InvalidScopeException the scope is incomplete or invalid
     * @throws OAuthException if this is catched, no other {@link org.gerstner.oauth2android.exception.OAuthException} extending Exception will be thrown.
     * @throws IOException a connection error occurred during the request
     */
    public Response executeAccessTokenRequest()
        throws InvalidRequestException, InvalidTokenTypeException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException, IOException {

        List<NameValuePair> parameter = prepareAccessTokenRequest();

        parameter.add(new BasicNameValuePair("grant_type", "client_credentials"));
        return getTokens(parameter);
    }

    /**
     * Executes the Request for an Access-Token by transmitting the <b>client credentials</b> and additional parameters. This method is used
     * only under specific circumstances e.g. when the client is the actual resource owner of the resources he
     * wants to access with the requested access token.
     * The access token and the refresh token (if any) are automatically assigned to the client instance.
     * See the OAuth 2.0 specification for more details.<br>
     * Under <i>normal</i> circumstances one might call the {@link #executeAccessTokenRequest(java.lang.String)} method.
     * <br><br>
     * Other methods are:
     * <ul>
     * <li>{@link #executeAccessTokenRequest()}  - transmitting only the <b>client credentials</b> but without a <code>List</code> of additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String)} - used under <i>normal</i> circumstances to get an access token with the <b>authorization code</b></li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.util.List)} - also to transmit the <b>authorization code</b> but with additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.lang.String)} - used to transmit the users <b>password credentials</b> directly</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.lang.String, java.util.List)} - also to transmit the users <b>password credentials</b> directly but with additional parameters</li>
     * </ul>
     * @param additionalParameter user defined parameters for the request (see the service providers API documentation)
     * @return Response containing the AccessToken or an error message from the server.
     * @throws InvalidRequestException the request is missing a parameter or is otherwise invalid
     * @throws InvalidTokenTypeException the server did not specify which token type to expect or the wrong token type was received.
     * @throws InvalidClientException the client could not be identified
     * @throws InvalidGrantException the authorization grant is not valid
     * @throws UnauthorizedClientException the token is not valid or is of the wrong type
     * @throws UnsupportedGrantTypeException the client used an unsupported method for the authorization grant
     * @throws InvalidScopeException the scope is incomplete or invalid
     * @throws OAuthException if this is catched, no other {@link org.gerstner.oauth2android.exception.OAuthException} extending Exception will be thrown.
     * @throws IOException a connection error occurred during the request
     */
    public Response executeAccessTokenRequest(List<NameValuePair> additionalParameter)
        throws InvalidRequestException, InvalidTokenTypeException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException, IOException {

        List<NameValuePair> parameter = prepareAccessTokenRequest();

        parameter.add(new BasicNameValuePair("grant_type", "client_credentials"));

        parameter.addAll(additionalParameter);

        return getTokens(parameter);
    }

    /**
     * Executes the Request for an Access-Token by transmitting the <b>authorization code</b> with additional parameters. This method is <i>normally</i> used.
     * The access token and the refresh token (if any) are automatically assigned to the client instance.
     * See the OAuth 2.0 specification for more details.<br>
     * <br><br>
     * Other methods are:
     * <ul>
     * <li>{@link #executeAccessTokenRequest()}  - transmitting only the <b>client credentials</b> but without a <code>List</code> of additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.util.List)}  -  transmitting only the <b>client credentials</b> but with a <code>List</code> of additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.util.List)} - also to transmit the <b>authorization code</b> but with additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.lang.String)} - used to transmit the users <b>password credentials</b> directly</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.lang.String, java.util.List)} - also to transmit the users <b>password credentials</b> directly but with additional parameters</li>
     * </ul>
     * @return Response containing the AccessToken or an error message from the server.
     * @throws InvalidRequestException the request is missing a parameter or is otherwise invalid
     * @throws InvalidTokenTypeException the server did not specify which token type to expect or the wrong token type was received.
     * @throws InvalidClientException the client could not be identified
     * @throws InvalidGrantException the authorization grant is not valid
     * @throws UnauthorizedClientException the token is not valid or is of the wrong type
     * @throws UnsupportedGrantTypeException the client used an unsupported method for the authorization grant
     * @throws InvalidScopeException the scope is incomplete or invalid
     * @throws OAuthException if this is catched, no other {@link org.gerstner.oauth2android.exception.OAuthException} extending Exception will be thrown.
     * @throws IOException a connection error occurred during the request
     */
    public Response executeAccessTokenRequest(String authorizationCode)
        throws InvalidRequestException, InvalidTokenTypeException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException, IOException {

        List<NameValuePair> parameter = prepareAccessTokenRequest();

        parameter.add(new BasicNameValuePair("grant_type", "authorization_code"));
        parameter.add(new BasicNameValuePair("code", authorizationCode));

        return getTokens(parameter);
    }

    /**
     * Executes the Request for an Access-Token by transmitting the <b>authorization code</b>. This method is <i>normally</i> used.
     * The access token and the refresh token (if any) are automatically assigned to the client instance.
     * See the OAuth 2.0 specification for more details.<br>
     * <br><br>
     * Other methods are:
     * <ul>
     * <li>{@link #executeAccessTokenRequest()}  - transmitting only the <b>client credentials</b> but without a <code>List</code> of additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.util.List)}  -  transmitting only the <b>client credentials</b> but with a <code>List</code> of additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String)} - used under <i>normal</i> circumstances to get an access token with the <b>authorization code</b></li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.lang.String)} - used to transmit the users <b>password credentials</b> directly</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.lang.String, java.util.List)} - also to transmit the users <b>password credentials</b> directly but with additional parameters</li>
     * </ul>
     * @param additionalParameter user defined parameters for the request (see the service providers API documentation)
     * @return Response containing the AccessToken or an error message from the server.
     * @throws InvalidRequestException the request is missing a parameter or is otherwise invalid
     * @throws InvalidTokenTypeException the server did not specify which token type to expect or the wrong token type was received.
     * @throws InvalidClientException the client could not be identified
     * @throws InvalidGrantException the authorization grant is not valid
     * @throws UnauthorizedClientException the token is not valid or is of the wrong type
     * @throws UnsupportedGrantTypeException the client used an unsupported method for the authorization grant
     * @throws InvalidScopeException the scope is incomplete or invalid
     * @throws OAuthException if this is catched, no other {@link org.gerstner.oauth2android.exception.OAuthException} extending Exception will be thrown.
     * @throws IOException a connection error occurred during the request
     */
    public Response executeAccessTokenRequest(String authorizationCode, List<NameValuePair> additionalParameter)
        throws InvalidRequestException, InvalidTokenTypeException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException, IOException {

        List<NameValuePair> parameter = prepareAccessTokenRequest();

        parameter.add(new BasicNameValuePair("grant_type", "authorization_code"));
        parameter.add(new BasicNameValuePair("code", authorizationCode));

        parameter.addAll(additionalParameter);

        return getTokens(parameter);
    }

    /**
     * Executes the Request for an Access-Token by transmitting the <b>resource owners password credentials </b> (username and password). This method should only be used under special circumstances
     * and with great care.
     * The access token and the refresh token (if any) are automatically assigned to the client instance.
     * See the OAuth 2.0 specification for more details.<br>
     * <br><br>
     * Other methods are:
     * <ul>
     * <li>{@link #executeAccessTokenRequest()}  - transmitting only the <b>client credentials</b> but without a <code>List</code> of additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.util.List)}  -  transmitting only the <b>client credentials</b> but with a <code>List</code> of additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String)} - used under <i>normal</i> circumstances to get an access token with the <b>authorization code</b></li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.util.List)} - also to transmit the <b>authorization code</b> but with additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.lang.String, java.util.List)} - also to transmit the users <b>password credentials</b> directly but with additional parameters</li>
     * </ul>
     * @return Response containing the AccessToken or an error message from the server.
     * @throws InvalidRequestException the request is missing a parameter or is otherwise invalid
     * @throws InvalidTokenTypeException the server did not specify which token type to expect or the wrong token type was received.
     * @throws InvalidClientException the client could not be identified
     * @throws InvalidGrantException the authorization grant is not valid
     * @throws UnauthorizedClientException the token is not valid or is of the wrong type
     * @throws UnsupportedGrantTypeException the client used an unsupported method for the authorization grant
     * @throws InvalidScopeException the scope is incomplete or invalid
     * @throws OAuthException if this is catched, no other {@link org.gerstner.oauth2android.exception.OAuthException} extending Exception will be thrown.
     * @throws IOException a connection error occurred during the request
     */
    public Response executeAccessTokenRequest(String username, String password)
        throws InvalidRequestException, InvalidTokenTypeException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException, IOException {

        List<NameValuePair> parameter = prepareAccessTokenRequest();

        parameter.add(new BasicNameValuePair("grant_type", "password"));
        parameter.add(new BasicNameValuePair("username", username));
        parameter.add(new BasicNameValuePair("password", password));

        return getTokens(parameter);
    }

    /**
     * Executes the Request for an Access-Token by transmitting the <b>resource owners password credentials </b> (username and password) and additional parameters. This method should only be used under special circumstances
     * and with great care.
     * The access token and the refresh token (if any) are automatically assigned to the client instance.
     * See the OAuth 2.0 specification for more details.<br>
     * <br><br>
     * Other methods are:
     * <ul>
     * <li>{@link #executeAccessTokenRequest()}  - transmitting only the <b>client credentials</b> but without a <code>List</code> of additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.util.List)}  -  transmitting only the <b>client credentials</b> but with a <code>List</code> of additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String)} - used under <i>normal</i> circumstances to get an access token with the <b>authorization code</b></li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.util.List)} - also to transmit the <b>authorization code</b> but with additional parameters</li>
     * <li>{@link #executeAccessTokenRequest(java.lang.String, java.lang.String)} - used to transmit the users <b>password credentials</b> directly</li>
     * </ul>
     * @param additionalParameter user defined parameters for the request (see the service providers API documentation)
     * @return Response containing the AccessToken or an error message from the server.
     * @throws InvalidRequestException the request is missing a parameter or is otherwise invalid
     * @throws InvalidTokenTypeException the server did not specify which token type to expect or the wrong token type was received.
     * @throws InvalidClientException the client could not be identified
     * @throws InvalidGrantException the authorization grant is not valid
     * @throws UnauthorizedClientException the token is not valid or is of the wrong type
     * @throws UnsupportedGrantTypeException the client used an unsupported method for the authorization grant
     * @throws InvalidScopeException the scope is incomplete or invalid
     * @throws OAuthException if this is catched, no other {@link org.gerstner.oauth2android.exception.OAuthException} extending Exception will be thrown.
     * @throws IOException a connection error occurred during the request
     */
    public Response executeAccessTokenRequest(String username, String password, List<NameValuePair> additionalParameter)
        throws InvalidRequestException, InvalidTokenTypeException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException, IOException {

        List<NameValuePair> parameter = prepareAccessTokenRequest();

        parameter.add(new BasicNameValuePair("grant_type", "password"));
        parameter.add(new BasicNameValuePair("username", username));
        parameter.add(new BasicNameValuePair("password", password));

        parameter.addAll(additionalParameter);

        return getTokens(parameter);
    }

    /******************************************************************
     ***************** PROTECTED RESOURCE REQUEST *********************
     ******************************************************************/
    /**
     * Executes a request for the protected resources.<br>
     * The request is directed to the given url of the Resource-Server, where as the resource endpoint directs the request to the
     * specified resource. Additional parameters can be defined to specify the request (see the service providers API documentation for more details.
     * If the request does not require the use of the http POST method, see {@link org.gerstner.oauth2android.common.Connection} for other standard methods.
     * @param requestUri <code>string</code> containing the part of the url that leads to the resource
     * @param parameter <code>list</code> with additional parameters to specify the resource
     * @param httpMethod <code>string</code> that specifies the http method that should be used (e.g. GET, POST...)
     * @return Response containing the requested Resources or an error message from the server.
     * @throws InvalidRequestException the request is missing a parameter or is otherwise invalid
     * @throws InvalidTokenTypeException the server did not specify which token type to expect or the wrong token type was received.
     * @throws InvalidClientException the client could not be identified
     * @throws InvalidGrantException the authorization grant is not valid
     * @throws UnauthorizedClientException the token is not valid or is of the wrong type
     * @throws UnsupportedGrantTypeException the client used an unsupported method for the authorization grant
     * @throws InvalidScopeException the scope is incomplete or invalid
     * @throws OAuthException if this is catched, no other {@link org.gerstner.oauth2android.exception.OAuthException} extending Exception will be thrown.
     * @throws IOException a connection error occurred during the request
     * @throws InvalidTokenTypeException if the specified token is not of the type the server expects
     * @see #executeProtectedResourceRequest(java.lang.String, java.util.List)
     */
    public Response executeProtectedResourceRequest(String requestUri, List<NameValuePair> parameter, String httpMethod)
        throws InvalidRequestException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException, IOException, InvalidTokenTypeException {

        requestUri = (requestUri.startsWith("/")) ? requestUri : "/" + requestUri;
        HttpClient httpClient = new DefaultHttpClient();
        Response response;

        if (httpMethod.equalsIgnoreCase(Connection.HTTP_METHOD_DELETE)) {
            HttpDelete authorizedHttpDelete = this.tokenTypeDefinition.getAuthorizedHttpDelete(parameter, requestUri, server, client, server.useAuthorizationHeader());
            response = new Response(httpClient.execute(authorizedHttpDelete));
        } else if (httpMethod.equalsIgnoreCase(Connection.HTTP_METHOD_GET)) {
            HttpGet authorizedHttpGet = this.tokenTypeDefinition.getAuthorizedHttpGet(parameter, requestUri, server, client, server.useAuthorizationHeader());
            response = new Response(httpClient.execute(authorizedHttpGet));
        } else if (httpMethod.equalsIgnoreCase(Connection.HTTP_METHOD_PUT)) {
            HttpPut authorizedHttpPut = this.tokenTypeDefinition.getAuthorizedHttpPut(parameter, requestUri, server, client, server.useAuthorizationHeader());
            response = new Response(httpClient.execute(authorizedHttpPut));
        } else if (httpMethod == null || httpMethod.equalsIgnoreCase("")) {
            response = executeProtectedResourceRequest(requestUri, parameter, httpMethod);
        } else {
            HttpPost authorizedHttpPost = this.tokenTypeDefinition.getAuthorizedHttpPost(parameter, requestUri, server, client, server.useAuthorizationHeader());
            response = new Response(httpClient.execute(authorizedHttpPost));
        }

        return response;
    }

    /**
     * Executes a request for the protected resources.<br>
     * The request is directed to the given url of the Resource-Server, where as the resource endpoint directs the request to the
     * specified resource. Additional parameters can be defined to specify the request (see the service providers API documentation for more details.
     * @param requestUri <code>string</code> containing the part of the url that leads to the resource
     * @return Response containing the requested Resources or an error message from the server.
     * @throws InvalidRequestException the request is missing a parameter or is otherwise invalid
     * @throws InvalidTokenTypeException the server did not specify which token type to expect or the wrong token type was received.
     * @throws InvalidClientException the client could not be identified
     * @throws InvalidGrantException the authorization grant is not valid
     * @throws UnauthorizedClientException the token is not valid or is of the wrong type
     * @throws UnsupportedGrantTypeException the client used an unsupported method for the authorization grant
     * @throws InvalidScopeException the scope is incomplete or invalid
     * @throws OAuthException if this is catched, no other {@link org.gerstner.oauth2android.exception.OAuthException} extending Exception will be thrown.
     * @throws IOException a connection error occurred during the request
     * @throws InvalidTokenTypeException if the specified token is not of the type the server expects
     * @see #executeProtectedResourceRequest(java.lang.String, java.util.List, java.lang.string)
     */
    public Response executeProtectedResourceRequest(String requestUri, List<NameValuePair> parameter)
        throws InvalidRequestException,
               InvalidClientException, InvalidGrantException,
               UnauthorizedClientException, UnsupportedGrantTypeException,
               InvalidScopeException, OAuthException, IOException, InvalidTokenTypeException {
        requestUri = (requestUri.startsWith("/")) ? requestUri : "/" + requestUri;
        HttpClient httpClient = new DefaultHttpClient();
        Response response;
        if (server.getPreferredHttpMethod().equalsIgnoreCase(Connection.HTTP_METHOD_DELETE)) {
            HttpDelete authorizedHttpDelete = this.tokenTypeDefinition.getAuthorizedHttpDelete(parameter, requestUri, server, client, server.useAuthorizationHeader());
            response = new Response(httpClient.execute(authorizedHttpDelete));
        } else if (server.getPreferredHttpMethod().equalsIgnoreCase(Connection.HTTP_METHOD_GET)) {
            HttpGet authorizedHttpGet = this.tokenTypeDefinition.getAuthorizedHttpGet(parameter, requestUri, server, client, server.useAuthorizationHeader());
            response = new Response(httpClient.execute(authorizedHttpGet));
        } else if (server.getPreferredHttpMethod().equalsIgnoreCase(Connection.HTTP_METHOD_PUT)) {
            HttpPut authorizedHttpPut = this.tokenTypeDefinition.getAuthorizedHttpPut(parameter, requestUri, server, client, server.useAuthorizationHeader());
            response = new Response(httpClient.execute(authorizedHttpPut));
        } else {
            HttpPost authorizedHttpPost = this.tokenTypeDefinition.getAuthorizedHttpPost(parameter, requestUri, server, client, server.useAuthorizationHeader());
            response = new Response(httpClient.execute(authorizedHttpPost));
        }

        return response;
    }

    /**
     * With this method the RefreshToken (if any) is used to refresh the AccessToken. Therefore
     * it presents the RefreshToken in a basic http Authorization Header. <br>
     * You may use GET for the http Method, but it is recommended to use POST. If
     * the <code>method</code> parameter is empty POST will be used.<br>
     * The result is an Response-Instance containing the new Access-Token or throwing
     * an Exception if the server responds with an error.
     * @param method <code>String</code> value of the http-method used.
     * @throws InvalidRequestException the request is missing a parameter or is otherwise invalid
     * @throws InvalidClientException the client could not be identified
     * @throws InvalidGrantException the authorization grant is not valid
     * @throws UnauthorizedClientException the token is not valid or is of the wrong type
     * @throws UnsupportedGrantTypeException the client used an unsupported method for the authorization grant
     * @throws InvalidScopeException the token is incomplete or invalid
     * @throws OAuthException if this is catched, no other {@link org.gerstner.oauth2android.exception.OAuthException} extending Exception will be thrown.
     * @throws IOException a connection error occurred during the request
     */
    public void refreshAccessToken(String method)
        throws IOException, InvalidRequestException, InvalidClientException, InvalidGrantException, UnauthorizedClientException, UnsupportedGrantTypeException, InvalidScopeException, OAuthException {

        Token refreshToken = client.getRefreshToken();
        if (refreshToken == null || !refreshToken.getType().equalsIgnoreCase("RefreshToken")) {
            throw new InvalidTokenTypeException("The refresh roken is either empty or it is not a refresh token");
        }

        Response response = ((RefreshToken) this.client.getRefreshToken()).executeRefreshRequest(client, server, method);
        client.setAccessToken(response.getAccessToken());
        client.setRefreshToken(response.getRefreshToken());
    }
}
