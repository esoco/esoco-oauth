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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.scribe.builder.api.DefaultApi20;
import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;


/********************************************************************
 * Google OAuth2.0 Released under the same license as scribe (MIT License).
 *
 * <p>[eso] Modified to set the access_type request parameter to 'offline' and
 * include_granted_scopes to 'true'. The returned access token contains the
 * refresh token in it's 'secret' field.</p>
 *
 * @author yincrash
 * @see    https://gist.github.com/yincrash/2465453
 */
public class GoogleApi20 extends DefaultApi20
{
	//~ Static fields/initializers ---------------------------------------------

	private static final String AUTHORIZE_URL =
		"https://accounts.google.com/o/oauth2/auth?response_type=code" +
		"&access_type=offline&include_granted_scopes=true" +
		"&client_id=%s&redirect_uri=%s";

	private static final String SCOPED_AUTHORIZE_URL =
		AUTHORIZE_URL + "&scope=%s";

	private static final String JSON_FIELD_PATTERN =
		"\"%s\"\\s*:\\s*\"([^&\"]+)\"";

	/**
	 * A constant for the name of the refresh token parameter or response field.
	 */
	public static final String REFRESH_TOKEN = "refresh_token";

	/** A constant for the name of the grant type parameter. */
	public static final String GRANT_TYPE = "grant_type";

	private static final String GRANT_TYPE_AUTHORIZATION_CODE =
		"authorization_code";

	//~ Static methods ---------------------------------------------------------

	/***************************************
	 * Returns the value of a field from a string that contains an OAuth
	 * response in JSON format.
	 *
	 * @param  sResponse     The input string in JSON format
	 * @param  sField        The name of the field to return the value of
	 * @param  sDefaultValue The default value to return if the field doesn't
	 *                       exist
	 *
	 * @return The field value or NULL if not found
	 */
	public static String getResponseFieldValue(String sResponse,
											   String sField,
											   String sDefaultValue)
	{
		Matcher aMatcher =
			Pattern.compile(String.format(JSON_FIELD_PATTERN, sField))
				   .matcher(sResponse);

		return aMatcher.find() ? OAuthEncoder.decode(aMatcher.group(1))
							   : sDefaultValue;
	}

	//~ Methods ----------------------------------------------------------------

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	public OAuthService createService(OAuthConfig rConfig)
	{
		return new GoogleServiceImpl(this, rConfig);
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	public String getAccessTokenEndpoint()
	{
		return "https://accounts.google.com/o/oauth2/token";
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	public AccessTokenExtractor getAccessTokenExtractor()
	{
		return new AccessTokenExtractor()
		{
			@Override
			public Token extract(String sResponse)
			{
				Preconditions.checkEmptyString(sResponse,
											   "Response body is incorrect. " +
											   "Can't extract a token from an " +
											   "empty string");

				String sAccessToken =
					getResponseFieldValue(sResponse,
										  OAuthConstants.ACCESS_TOKEN,
										  "");

				if (sAccessToken != null && sAccessToken.length() > 0)
				{
					String sRefreshToken =
						getResponseFieldValue(sResponse, REFRESH_TOKEN, "");

					return new Token(sAccessToken, sRefreshToken, sResponse);
				}
				else
				{
					throw new OAuthException("Response body is incorrect. " +
											 "Can't extract a token from '" +
											 sResponse + "'",
											 null);
				}
			}
		};
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	public Verb getAccessTokenVerb()
	{
		return Verb.POST;
	}

	/***************************************
	 * {@inheritDoc}
	 */
	@Override
	public String getAuthorizationUrl(OAuthConfig rConfig)
	{
		if (rConfig.hasScope())
		{
			return String.format(SCOPED_AUTHORIZE_URL,
								 rConfig.getApiKey(),
								 OAuthEncoder.encode(rConfig.getCallback()),
								 OAuthEncoder.encode(rConfig.getScope()));
		}
		else
		{
			return String.format(AUTHORIZE_URL,
								 rConfig.getApiKey(),
								 OAuthEncoder.encode(rConfig.getCallback()));
		}
	}

	//~ Inner Classes ----------------------------------------------------------

	/********************************************************************
	 * Google OAuth2.0 Released under the same license as scribe (MIT License)
	 *
	 * @author yincrash
	 * @see    https://gist.github.com/yincrash/2465453
	 */
	private class GoogleServiceImpl extends OAuth20ServiceImpl
	{
		//~ Instance fields ----------------------------------------------------

		private GoogleApi20 rApi;
		private OAuthConfig rConfig;

		//~ Constructors -------------------------------------------------------

		/***************************************
		 * Creates a new instance.
		 *
		 * @param rApi    The Google OAuth 2.0 API
		 * @param rConfig The configuration
		 */
		public GoogleServiceImpl(GoogleApi20 rApi, OAuthConfig rConfig)
		{
			super(rApi, rConfig);

			this.rApi    = rApi;
			this.rConfig = rConfig;
		}

		//~ Methods ------------------------------------------------------------

		/***************************************
		 * {@inheritDoc}
		 */
		@Override
		public Token getAccessToken(Token rRequestToken, Verifier rVerifier)
		{
			OAuthRequest rRequest =
				new OAuthRequest(rApi.getAccessTokenVerb(),
								 rApi.getAccessTokenEndpoint());

			rRequest.addBodyParameter(OAuthConstants.CLIENT_ID,
									  rConfig.getApiKey());
			rRequest.addBodyParameter(OAuthConstants.CLIENT_SECRET,
									  rConfig.getApiSecret());
			rRequest.addBodyParameter(OAuthConstants.CODE,
									  rVerifier.getValue());
			rRequest.addBodyParameter(OAuthConstants.REDIRECT_URI,
									  rConfig.getCallback());
			rRequest.addBodyParameter(GRANT_TYPE,
									  GRANT_TYPE_AUTHORIZATION_CODE);

			String sResponse = rRequest.send().getBody();

			return rApi.getAccessTokenExtractor().extract(sResponse);
		}
	}
}
