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

import de.esoco.lib.net.ExternalServiceDefinition;
import de.esoco.lib.net.ServiceDefinitionImpl;

import de.esoco.storage.StorageException;

import java.util.Collection;

import org.obrel.core.RelationType;
import org.obrel.core.RelationTypes;

import org.scribe.builder.api.Api;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.oauth.OAuthService;

import static de.esoco.entity.ExtraAttributes.newExtraAttribute;

import static de.esoco.lib.net.oauth.GoogleApi20.GRANT_TYPE;
import static de.esoco.lib.net.oauth.GoogleApi20.REFRESH_TOKEN;
import static de.esoco.lib.net.oauth.GoogleApi20.getResponseFieldValue;

import static org.obrel.core.RelationTypes.newType;


/********************************************************************
 * Implementation of the external service access for Google with the OAuth 2.0
 * protocol. Based on the {@link GoogleApi20} OAuth service implementation.
 *
 * @author eso
 */
public class GoogleOAuth20Service extends ExternalOAuthService
{
	//~ Static fields/initializers ---------------------------------------------

	private static final String REQUEST_ID_PARAM = "state";

	private static final RelationType<String> GOOGLE_API_KEY    =
		newExtraAttribute();
	private static final RelationType<String> GOOGLE_API_SECRET =
		newExtraAttribute();

	private static final RelationType<String> GOOGLE_OAUTH_REFRESH_TOKEN =
		newExtraAttribute();

	private static final RelationType<String> GOOGLE_OAUTH_ACCESS_TOKEN =
		newType();

	private static final String ACCESS_TOKEN_VALIDATION_URL =
		"https://www.googleapis.com/oauth2/v1/tokeninfo";

	private static final String REFRESH_ACCESS_TOKEN_URL =
		"https://accounts.google.com/o/oauth2/token";

	static
	{
		RelationTypes.init(GoogleOAuth20Service.class);
	}

	//~ Static methods ---------------------------------------------------------

	/***************************************
	 * Returns a new google OAuth service definition with the given access
	 * scopes.
	 *
	 * @param  rAccessScopes The Google access scopes the service shall support
	 *
	 * @return A new service definition instance
	 */
	public static final ExternalServiceDefinition createServiceDefinition(
		Collection<String> rAccessScopes)
	{
		return new ServiceDefinitionImpl(GoogleOAuth20Service.class,
										 "https://www.googleapis.com/auth/",
										 rAccessScopes);
	}

	//~ Methods ----------------------------------------------------------------

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	public String getRequestIdParam()
	{
		return REQUEST_ID_PARAM;
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	protected String appendForceAuthorization(String sAuthUrl)
	{
		return sAuthUrl + "&approval_prompt=force";
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	protected String appendRequestId(String sAuthUrl, String sRequestId)
	{
		return String.format("%s&" + REQUEST_ID_PARAM + "=%s",
							 sAuthUrl,
							 sRequestId);
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	protected RelationType<String> getAccessTokenRelationType()
	{
		return GOOGLE_OAUTH_ACCESS_TOKEN;
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	protected Class<? extends Api> getApi()
	{
		return GoogleApi20.class;
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	protected String getApiKey()
	{
		return getRequiredConfigValue(GOOGLE_API_KEY);
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	protected String getApiSecret()
	{
		return getRequiredConfigValue(GOOGLE_API_SECRET);
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	protected RelationType<String> getRefreshTokenExtraAttribute()
	{
		return GOOGLE_OAUTH_REFRESH_TOKEN;
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	protected boolean isAccessTokenValid(
		String    sAccessToken,
		Object... rAccessScopes) throws Exception
	{
		OAuthService rOAuthService = getOAuthService(null, rAccessScopes);
		OAuthRequest aRequest	   =
			new OAuthRequest(Verb.GET, ACCESS_TOKEN_VALIDATION_URL);

		rOAuthService.signRequest(new Token(sAccessToken, ""), aRequest);

		Response rResponse     = aRequest.send();
		String   sResponseText = rResponse.getBody();

		String sCurrentScopes =
			getResponseFieldValue(sResponseText, "scope", "");

		for (Object rScope : rAccessScopes)
		{
			if (!sCurrentScopes.contains(rScope.toString()))
			{
				return false;
			}
		}

		return true;
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	protected String refreshAccessToken(String sRefreshToken)
		throws StorageException
	{
		OAuthRequest rRequest =
			new OAuthRequest(Verb.POST, REFRESH_ACCESS_TOKEN_URL);

		rRequest.addBodyParameter(GRANT_TYPE, REFRESH_TOKEN);
		rRequest.addBodyParameter(REFRESH_TOKEN, sRefreshToken);
		rRequest.addBodyParameter(OAuthConstants.CLIENT_ID, getApiKey());
		rRequest.addBodyParameter(OAuthConstants.CLIENT_SECRET, getApiSecret());

		Response rResponse = rRequest.send();

		return getResponseFieldValue(rResponse.getBody(),
									 OAuthConstants.ACCESS_TOKEN,
									 null);
	}
}
