//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// This file is a part of the 'esoco-oauth' project.
// Copyright 2015 Elmar Sonnenschein, esoco GmbH, Flensburg, Germany
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
package de.esoco.lib.net.oauth;

import de.esoco.entity.Configuration;
import de.esoco.entity.Entity;
import de.esoco.entity.EntityManager;

import de.esoco.lib.collection.CollectionUtil;
import de.esoco.lib.logging.Log;
import de.esoco.lib.net.ExternalService;
import de.esoco.lib.net.ExternalServiceRequest;
import de.esoco.lib.net.ExternalServiceResponse;

import java.net.URL;

import javax.naming.AuthenticationException;

import org.obrel.core.RelationType;

import org.scribe.builder.ServiceBuilder;
import org.scribe.builder.api.Api;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Request;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuthService;


/********************************************************************
 * A base class that defines the access to an external service.
 *
 * @author eso
 */
public abstract class ExternalOAuthService extends ExternalService
{
	//~ Instance fields --------------------------------------------------------

	private OAuthService aOAuthService;

	//~ Methods ----------------------------------------------------------------

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	public Object authorizeAccess(String    sCallbackUrl,
								  boolean   bForceAuth,
								  Object... rAccessScopes) throws Exception
	{
		RelationType<String> rAccessTokenType = getAccessTokenRelationType();
		RelationType<String> rRefreshTokenXA  = getRefreshTokenExtraAttribute();

		Entity		  rUser		    = getUser();
		Configuration rSettings     = Configuration.getSettings(rUser, false);
		String		  sAccessToken  = rUser.get(rAccessTokenType);
		String		  sRefreshToken = null;
		Object		  rResult	    = null;

		if (rSettings != null)
		{
			sRefreshToken = rSettings.getExtraAttribute(rRefreshTokenXA, null);
		}

		if (bForceAuth)
		{
			sAccessToken  = null;
			sRefreshToken = null;

			rUser.set(rAccessTokenType, null);

			if (rSettings != null)
			{
				rSettings.setExtraAttribute(rRefreshTokenXA, null);
				EntityManager.storeEntity(rSettings, rUser);
			}
		}
		else
		{
			try
			{
				if (sAccessToken != null &&
					!isAccessTokenValid(sAccessToken, rAccessScopes))
				{
					sAccessToken = null;
				}

				if (sAccessToken == null && sRefreshToken != null)
				{
					sAccessToken = refreshAccessToken(sRefreshToken);
				}
			}
			catch (Exception e)
			{
				Log.infof(e,
						  "Token refresh failed for %s[%s]",
						  getClass().getSimpleName(),
						  rUser);
				sAccessToken = null;
			}

			rUser.set(rAccessTokenType, sAccessToken);
		}

		rResult = sAccessToken;

		if (sAccessToken == null)
		{
			OAuthService aService =
				getOAuthService(sCallbackUrl, rAccessScopes);

			String sAuthUrl =
				aService.getAuthorizationUrl(getRequestToken(aService));

			if (bForceAuth)
			{
				sAuthUrl = appendForceAuthorization(sAuthUrl);
			}

			rResult = new URL(appendRequestId(sAuthUrl, getServiceId()));
		}

		return rResult;
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	public ExternalServiceRequest createRequest(
		AccessType eAccessType,
		String	   sRequestUrl) throws Exception
	{
		OAuthRequest aRequest =
			new OAuthRequest(Verb.valueOf(eAccessType.name()), sRequestUrl);

		String sToken = getUser().get(getAccessTokenRelationType());

		if (sToken != null)
		{
			Token aAccessToken = new Token(sToken, "");

			getOAuthService(null).signRequest(aAccessToken, aRequest);
		}
		else
		{
			throw new AuthenticationException("External service access not authorized");
		}

		return new OAuthExternalServiceRequest(aRequest);
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	public String getCallbackCodeRequestParam()
	{
		return OAuthConstants.CODE;
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	public String processCallback(String sCallbackCode) throws Exception
	{
		Verifier aVerifier = new Verifier(sCallbackCode);
		Entity   rUser     = getUser();

		Token rToken =
			aOAuthService.getAccessToken(getRequestToken(aOAuthService),
										 aVerifier);

		String sAccessToken  = rToken.getToken();
		String sRefreshToken = rToken.getSecret();

		rUser.set(getAccessTokenRelationType(), sAccessToken);

		if (sRefreshToken.isEmpty())
		{
			sRefreshToken = null;
		}

		Configuration rSettings = Configuration.getSettings(rUser, true);

		rSettings.setExtraAttribute(getRefreshTokenExtraAttribute(),
									sRefreshToken);
		EntityManager.storeEntity(rSettings, rUser);

		return sAccessToken;
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	public void revokeAccess() throws Exception
	{
		RelationType<String> rAccessTokenType = getAccessTokenRelationType();
		RelationType<String> rRefreshTokenXA  = getRefreshTokenExtraAttribute();

		Entity		  rUser     = getUser();
		Configuration rSettings = Configuration.getSettings(rUser, false);

		rUser.set(rAccessTokenType, null);

		if (rSettings != null)
		{
			rSettings.setExtraAttribute(rRefreshTokenXA, null);
			EntityManager.storeEntity(rSettings, rUser);
		}
	}

	/***************************************
	 * Must be implemented to add the given request identifier to a new
	 * authorization URL.
	 *
	 * @param  sAuthUrl   The authorization URL
	 * @param  sRequestId The request ID to add to the URL
	 *
	 * @return The resulting URL
	 */
	protected abstract String appendRequestId(
		String sAuthUrl,
		String sRequestId);

	/***************************************
	 * Returns a relation type that will be used to store the current access
	 * token for this service.
	 *
	 * @return The refresh token user extra attribute
	 */
	protected abstract RelationType<String> getAccessTokenRelationType();

	/***************************************
	 * Returns the OAuth API implementation class for the external service.
	 *
	 * @return The API implementation class
	 */
	protected abstract Class<? extends Api> getApi();

	/***************************************
	 * Returns the key that is needed to access the OAuth API of this service.
	 *
	 * @return The API key
	 */
	protected abstract String getApiKey();

	/***************************************
	 * Returns the secret value that is needed to access the OAuth API of this
	 * service.
	 *
	 * @return The API secret
	 */
	protected abstract String getApiSecret();

	/***************************************
	 * Returns an extra attribute relation type that refers to the user's
	 * refresh token for the re-issuing of access tokens.
	 *
	 * @return The refresh token user extra attribute
	 */
	protected abstract RelationType<String> getRefreshTokenExtraAttribute();

	/***************************************
	 * Validates whether an existing access token can still be used to access
	 * the remote service.
	 *
	 * @param  sToken        The access token to check
	 * @param  rAccessScopes The access scopes for which the token must be valid
	 *
	 * @return TRUE if the access token is still valid
	 *
	 * @throws Exception If the operation fails
	 */
	protected abstract boolean isAccessTokenValid(
		String    sToken,
		Object... rAccessScopes) throws Exception;

	/***************************************
	 * Generates a new access token from a refresh token if supported by the
	 * underlying service.
	 *
	 * @param  sRefreshToken The refresh token
	 *
	 * @return The newly generated access token or NULL if none is available
	 *
	 * @throws Exception If the operation fails
	 */
	protected abstract String refreshAccessToken(String sRefreshToken)
		throws Exception;

	/***************************************
	 * Can be implemented to append a parameter that forces a re-authorization
	 * to the given URL if supported by the addressed service. The default
	 * implementation just returns the original URL.
	 *
	 * @param  sAuthUrl The authorization URL to amend
	 *
	 * @return The resulting URL
	 */
	protected String appendForceAuthorization(String sAuthUrl)
	{
		return sAuthUrl;
	}

	/***************************************
	 * Returns the OAuth service for this instance and creates it on demand.
	 *
	 * @param  sCallbackUrl  The callback URL for the access verification or
	 *                       NULL if not needed
	 * @param  rAccessScopes The optional access scopes to add to the service
	 *
	 * @return The OAuth service instance
	 *
	 * @throws Exception If initializing the service fails
	 */
	protected OAuthService getOAuthService(
		String    sCallbackUrl,
		Object... rAccessScopes) throws Exception
	{
		if (aOAuthService == null)
		{
			ServiceBuilder aServiceBuilder =
				new ServiceBuilder().provider(getApi()).apiKey(getApiKey())
									.apiSecret(getApiSecret());

			if (sCallbackUrl != null)
			{
				aServiceBuilder.callback(sCallbackUrl);
			}

			if (rAccessScopes.length > 0)
			{
				aServiceBuilder =
					aServiceBuilder.scope(CollectionUtil.toString(rAccessScopes,
																  "%20"));
			}

			aOAuthService = aServiceBuilder.build();
		}

		return aOAuthService;
	}

	/***************************************
	 * Helper method to return the request token from a certain OAuth service
	 * depending on the OAuth version.
	 *
	 * @param  rFromService The service to get the token from
	 *
	 * @return The request token (will be NULL for OAuth2)
	 */
	private Token getRequestToken(OAuthService rFromService)
	{
		// OAuth2 implementation throws an exception from getRequestToken()
		Token rRequestToken =
			rFromService.getVersion().startsWith("1")
			? rFromService.getRequestToken() : null;

		return rRequestToken;
	}

	//~ Inner Classes ----------------------------------------------------------

	/********************************************************************
	 * An {@link ExternalServiceRequest} wrapper for the scribe OAuth request.
	 *
	 * @author eso
	 */
	static class OAuthExternalServiceRequest implements ExternalServiceRequest
	{
		//~ Instance fields ----------------------------------------------------

		private final Request rRequest;

		//~ Constructors -------------------------------------------------------

		/***************************************
		 * Creates a new instance.
		 *
		 * @param rRequest The request to wrap
		 */
		OAuthExternalServiceRequest(Request rRequest)
		{
			this.rRequest = rRequest;
		}

		//~ Methods ------------------------------------------------------------

		/***************************************
		 * {@inheritDoc}
		 */
		@Override
		public ExternalServiceResponse send()
		{
			return new OAuthExternalServiceResponse(rRequest.send());
		}

		/***************************************
		 * {@inheritDoc}
		 */
		@Override
		public void setBody(String sBodyData)
		{
			rRequest.addPayload(sBodyData);
		}

		/***************************************
		 * {@inheritDoc}
		 */
		@Override
		public void setHeader(String sName, String sValue)
		{
			rRequest.addHeader(sName, sValue);
		}

		/***************************************
		 * {@inheritDoc}
		 */
		@Override
		public void setParameter(String sName, String sValue)
		{
			if (rRequest.getVerb() == Verb.GET)
			{
				rRequest.addQuerystringParameter(sName, sValue);
			}
			else
			{
				rRequest.addBodyParameter(sName, sValue);
			}
		}
	}

	/********************************************************************
	 * An {@link ExternalServiceResponse} wrapper for the scribe OAuth response.
	 *
	 * @author eso
	 */
	static class OAuthExternalServiceResponse implements ExternalServiceResponse
	{
		//~ Instance fields ----------------------------------------------------

		private final Response rResponse;

		//~ Constructors -------------------------------------------------------

		/***************************************
		 * Creates a new instance.
		 *
		 * @param rResponse The OAuth response to wrap
		 */
		OAuthExternalServiceResponse(Response rResponse)
		{
			this.rResponse = rResponse;
		}

		//~ Methods ------------------------------------------------------------

		/***************************************
		 * {@inheritDoc}
		 */
		@Override
		public int getCode()
		{
			return rResponse.getCode();
		}

		/***************************************
		 * {@inheritDoc}
		 */
		@Override
		public String getData()
		{
			return rResponse.getBody();
		}

		/***************************************
		 * {@inheritDoc}
		 */
		@Override
		public String getMessage()
		{
			return rResponse.getMessage();
		}
	}
}
