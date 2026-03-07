/*
 * OAuthProvider (abstract)
 * The contract every provider implementation must fulfill.
 * Extend this class to add support for any OAuth2 / OIDC provider.
 *
 * Example (minimal custom provider):
 *   class MyProvider extends OAuthProvider {
 *     MyProvider({required super.clientId, required super.clientSecret,
 *                 required super.redirectUri});
 *
 *     @override String get name => 'myprovider';
 *
 *     @override
 *     Future<OAuthSession> beginAuth({required StateStore stateStore,
 *                                     List<String> scopes = const []}) async {
 *       final pkce = PkceChallenge.generate();
 *       final state = generateState();
 *       await stateStore.save(state, StateEntry(...));
 *       final url = Uri.https('example.com', '/oauth/authorize', {
 *         'client_id': clientId,
 *         'redirect_uri': redirectUri,
 *         'state': state,
 *         'code_challenge': pkce.challenge,
 *         'code_challenge_method': 'S256',
 *       });
 *       return OAuthSession(authorizationUrl: url.toString(),
 *                           state: state, providerName: name);
 *     }
 *
 *     @override
 *     Future<OAuthUser> completeAuth({required Map<String,String> callbackParams,
 *                                     required StateStore stateStore}) async { ... }
 *
 *     @override Future<TokenSet> refreshToken(String refreshToken) async { ... }
 *   }
 */

import 'dart:convert';
import 'package:http/http.dart' as http;

import 'exceptions.dart';
import 'session.dart';
import 'state_store.dart';
import 'token.dart';
import 'user.dart';

export 'exceptions.dart';
export 'pkce.dart';
export 'session.dart';
export 'state_store.dart';
export 'token.dart';
export 'user.dart';

/// Configuration used when building OAuth2 authorization URLs.
class AuthConfig {
  /// Extra query parameters to append to the authorization URL.
  final Map<String, String> extraParams;

  /// Scopes to request in addition to the provider's defaults.
  final List<String> additionalScopes;

  /// If true, forces the provider to show the account picker (e.g. Google prompt=select_account).
  final bool forceAccountSelection;

  const AuthConfig({
    this.extraParams = const {},
    this.additionalScopes = const [],
    this.forceAccountSelection = false,
  });
}

/// Abstract base for all OAuth providers.
///
/// Concrete providers extend this class and implement [beginAuth],
/// [completeAuth], and [refreshToken].
///
/// Security properties guaranteed by this base:
/// - State generation is always cryptographically random.
/// - PKCE S256 is used by default where the provider supports it.
/// - State is always verified via timing-safe comparison.
abstract class OAuthProvider {
  /// OAuth client ID issued by the provider's developer console.
  final String clientId;

  /// OAuth client secret. NEVER expose in client-side code.
  /// [Nullable] for providers using PKCE-only public client flows.
  final String? clientSecret;

  /// Where the provider should redirect after authorization.
  /// Must match the URI registered in the provider's developer console exactly.
  final String redirectUri;

  /// Default scopes requested for every auth session.
  final List<String> defaultScopes;

  /// Whether to add PKCE to authorizatioon requests. Defaults to `true`.
  /// Set to `false` only for providers that do not support PKCE.
  final bool usePkce;

  /// HTTP client used for token exchange and user-info requests.
  /// Override to inject a mock in tests or add interceptors.
  final http.Client httpClient;

  OAuthProvider({
    required this.clientId,
    required this.redirectUri,
    this.clientSecret,
    this.defaultScopes = const [],
    this.usePkce = true,
    http.Client? httpClient,
  }) : httpClient = httpClient ?? http.Client();

  // ---------------------------------------------------------------
  // Identity
  // ---------------------------------------------------------------

  /// Canonical provider name (lowercase, no spaces). e.g. `'github'`, `'google'`.
  String get name;

  /// Human-readable display name. e.g. `'GitHub'`, `'Google'`.
  String get displayName => name[0].toUpperCase() + name.substring(1);

  /// Whether this provider supports a token refresh.
  bool get supportsRefresh => true;

  // ---------------------------------------------------------------------------
  // Abstract API — each provider must implement these
  // ---------------------------------------------------------------------------

  /*
     * beginAuth
     * Starts the OAuth flow: generates state + PKCE, builds the authorization URL,
     * persists the state entry, and returns an [OAuthSession].
     * Redirect the user to [OAuthSession.authorizationUrl].
     *
     * Example:
     *   final session = await provider.beginAuth(stateStore: stateStore);
     *   // In a shelf handler:
     *   return Response.found(session.authorizationUrl);
     */
  Future<OAuthSession> beginAuth({
    required StateStore stateStore,
    List<String> scopes = const [],
    AuthConfig config = const AuthConfig(),
  });

  /*
     * completeAuth
     * Handles the provider callback: validates state, exchanges the authorization
     * code for tokens, fetches the user profile, and returns an [OAuthUser].
     *
     * Example:
     *   final params = request.uri.queryParameters;
     *   final user = await provider.completeAuth(
     *     callbackParams: params,
     *     stateStore: stateStore,
     *   );
     */
  Future<OAuthUser> completeAuth({
    required Map<String, String> callbackParams,
    required StateStore stateStore,
  });

  /*
     * refreshToken
     * Exchanges a refresh token for a new [TokenSet].
     * Throws [TokenRefreshException] if the refresh fails.
     *
     * Example:
     *   final newTokens = await provider.refreshToken(user.refreshToken!);
     */
  Future<TokenSet> refreshToken(String refreshToken);

  // ---------------------------------------------------------------------------
  // Shared helpers (available to all provider subclasses)
  // ---------------------------------------------------------------------------

  /*
     * validateAndConsumeState
     * Verifies the callback state against the stored state using a timing-safe
     * comparison, then consumes (deletes) the state entry so it cannot be reused.
     * Throws [InvalidStateException] on any mismatch or expiry.
     *
     * Example:
     *   final entry = await validateAndConsumeState(callbackState, stateStore);
     *   final verifier = entry.pkceVerifier; // for token exchange
     */
  Future<StateEntry> validateAndConsumeState(
    String callbackState,
    StateStore stateStore,
  ) async {
    final entry = await stateStore.consume(callbackState);
    if (entry == null) {
      throw const InvalidStateException();
    }
    // Verify the state belongs to this provider to prevent cross-provider confusion.
    if (entry.providerName != name) {
      throw InvalidStateException(
        'State was issued for provider "${entry.providerName}" but '
        'callback hit provider "$name".',
      );
    }
    return entry;
  }

  /*
     * checkCallbackForErrors
     * Inspects standard OAuth error parameters returned in the callback URL.
     * Throws [ProviderErrorException] if the provider signalled an error.
     *
     * Example:
     *   checkCallbackForErrors(callbackParams); // throws if error present
     *   // safe to proceed with code exchange
     */
  void checkCallbackForErrors(Map<String, String> params) {
    final error = params['error'];
    if (error != null) {
      throw ProviderErrorException(
        errorCode: error,
        errorDescription: params['error_description'],
      );
    }
  }

  /*
     * postTokenEndpoint
     * Performs the authorization code → token exchange POST request.
     * Returns the decoded JSON response body.
     * Throws [TokenExchangeException] on HTTP errors.
     *
     * Example:
     *   final json = await postTokenEndpoint(
     *     tokenUrl,
     *     {'grant_type': 'authorization_code', 'code': code, ...},
     *   );
     */
  Future<Map<String, dynamic>> postTokenEndpoint(
    String tokenUrl,
    Map<String, String> body,
  ) async {
    final response = await httpClient.post(
      Uri.parse(tokenUrl),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
      },
      body: body,
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw TokenExchangeException(
        'Token endpoint returned HTTP ${response.statusCode}: ${response.body}',
        statusCode: response.statusCode,
      );
    }

    final Map<String, dynamic> json;
    try {
      json = jsonDecode(response.body) as Map<String, dynamic>;
    } catch (e) {
      throw TokenExchangeException(
        'Token endpoint returned non-JSON body: ${response.body}',
        cause: e,
      );
    }

    if (json.containsKey('error')) {
      throw TokenExchangeException(
        'Token endpoint error: ${json['error']} — ${json['error_description']}',
      );
    }

    return json;
  }

  /*
     * getWithBearerToken
     * Performs an authenticated GET to the provider's user-info endpoint.
     * Returns the decoded JSON response.
     * Throws [UserFetchException] on HTTP errors.
     *
     * Example:
     *   final profileJson = await getWithBearerToken(
     *     'https://api.github.com/user', accessToken);
     */
  Future<Map<String, dynamic>> getWithBearerToken(
    String url,
    String accessToken, {
    Map<String, String> extraHeaders = const {},
  }) async {
    final response = await httpClient.get(
      Uri.parse(url),
      headers: {
        'Authorization': 'Bearer $accessToken',
        'Accept': 'application/json',
        ...extraHeaders,
      },
    );

    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw UserFetchException(
        'User-info endpoint ${response.statusCode}: ${response.body}',
        statusCode: response.statusCode,
      );
    }

    try {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } catch (e) {
      throw UserFetchException('Failed to decode user JSON.', cause: e);
    }
  }

  /*
     * buildTokenSet
     * Constructs a [TokenSet] from a raw token endpoint response JSON map.
     *
     * Example:
     *   final tokens = buildTokenSet(tokenJson);
     *   // tokens.accessToken.value, tokens.refreshToken?.value
     */
  TokenSet buildTokenSet(Map<String, dynamic> json) {
    final rawExpiry = json['expires_in'];
    final expiry = rawExpiry is int
        ? DateTime.now().add(Duration(seconds: rawExpiry))
        : null;

    final scopes = (json['scope'] as String? ?? '')
        .split(RegExp(r'[\s,]+'))
        .where((s) => s.isNotEmpty)
        .toList();

    final accessToken = AccessToken(
      value: json['access_token'] as String,
      expiry: expiry,
      scopes: scopes,
    );

    RefreshToken? refreshToken;
    if (json['refresh_token'] is String) {
      refreshToken = RefreshToken(value: json['refresh_token'] as String);
    }

    IdToken? idToken;
    if (json['id_token'] is String) {
      idToken = IdToken(value: json['id_token'] as String);
    }

    return TokenSet(
      accessToken: accessToken,
      refreshToken: refreshToken,
      idToken: idToken,
    );
  }

  /*
     * mergeScopes
     * Combines provider default scopes with caller-supplied scopes,
     * deduplicating the result.
     *
     * Example:
     *   final scopes = mergeScopes(['repo', 'read:user']);
     *   // ['read:user', 'repo'] (default + extra, deduplicated)
     */
  List<String> mergeScopes(List<String> extra) {
    return {...defaultScopes, ...extra}.toList();
  }

  /// Frees the internal HTTP client. Call when the provider will no longer be used.
  void dispose() => httpClient.close();
}
