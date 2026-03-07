/*
 * OAuthSession
 * Captures transient state during an in-progress OAuth flow:
 * the authorization URL to redirect the user to, the state nonce,
 * and optional PKCE data.
 *
 * Example:
 *   final session = await provider.beginAuth(stateStore: stateStore);
 *   return Response.redirect(Uri.parse(session.authorizationUrl));
*/

/// Holds the data required to kick off and complete an OAuth exchange.
class OAuthSession {
  /// The URL the user should be redirected to for authorization.
  final String authorizationUrl;

  /// The random state value embedded in [authorizationUrl].
  /// Must be round-tripped and verified on callback.
  final String state;

  /// The PKCE challenge pair, if this session uses PKCE.
  /// The verifier is stored in [StateStore]; the challenge was sent to the
  /// provider. This field is exposed for testing purposes.
  final String? pkceChallenge;

  /// The provider that created this session.
  final String providerName;

  const OAuthSession({
    required this.authorizationUrl,
    required this.state,
    required this.providerName,
    this.pkceChallenge,
  });
}
