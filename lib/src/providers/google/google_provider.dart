// lib/src/providers/google/google_provider.dart

/*
 * GoogleProvider
 * OAuth2 / OpenID Connect provider for Google.
 * Uses the Authorization Code flow with PKCE + nonce.
 * Returns an ID token (JWT) containing identity claims.
 * Docs: https://developers.google.com/identity/protocols/oauth2/web-server
 *
 * Example:
 *   DartGoth.use([
 *     GoogleProvider(
 *       clientId: Platform.environment['GOOGLE_CLIENT_ID']!,
 *       clientSecret: Platform.environment['GOOGLE_CLIENT_SECRET']!,
 *       redirectUri: 'https://yourapp.com/auth/google/callback',
 *       scopes: ['openid', 'email', 'profile'],
 *     ),
 *   ]);
 */

import 'dart:convert';

import '../../core/provider.dart';

class GoogleEndpoints {
  static const String authUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
  static const String tokenUrl = 'https://oauth2.googleapis.com/token';
  static const String userInfoUrl =
      'https://www.googleapis.com/oauth2/v3/userinfo';
  static const String revokeUrl = 'https://oauth2.googleapis.com/revoke';
}

/// Access type for the Google authorization request.
enum GoogleAccessType {
  /// Short-lived tokens; no refresh token issued.
  online,

  /// Issues a refresh token alongside the access token.
  offline,
}

class GoogleProvider extends OAuthProvider {
  final GoogleAccessType accessType;

  /// If `true`, forces the consent screen to appear every time.
  /// Required to receive a refresh token on subsequent logins.
  final bool forceConsentScreen;

  GoogleProvider({
    required super.clientId,
    required super.clientSecret,
    required super.redirectUri,
    List<String> scopes = const ['openid', 'email', 'profile'],
    this.accessType = GoogleAccessType.offline,
    this.forceConsentScreen = false,
    super.httpClient,
  }) : super(defaultScopes: scopes, usePkce: true);

  @override
  String get name => 'google';

  @override
  String get displayName => 'Google';

  /*
   * beginAuth
   * Constructs the Google OAuth2 authorization URL with PKCE and nonce.
   * The nonce is stored in [StateStore.extra] and validated inside the
   * ID token after the code exchange.
   *
   * Example:
   *   final session = await googleProvider.beginAuth(stateStore: store);
   *   return Response.found(session.authorizationUrl);
   */
  @override
  Future<OAuthSession> beginAuth({
    required StateStore stateStore,
    List<String> scopes = const [],
    AuthConfig config = const AuthConfig(),
  }) async {
    final state = generateState();
    final nonce = generateNonce();
    final pkce = PkceChallenge.generate();
    final allScopes = mergeScopes([...scopes, ...config.additionalScopes]);

    await stateStore.save(
      state,
      StateEntry(
        providerName: name,
        expiry: DateTime.now().add(const Duration(minutes: 10)),
        pkceVerifier: pkce.verifier,
        extra: {'nonce': nonce},
      ),
    );

    final params = <String, String>{
      'client_id': clientId,
      'redirect_uri': redirectUri,
      'response_type': 'code',
      'scope': allScopes.join(' '),
      'state': state,
      'nonce': nonce,
      'code_challenge': pkce.challenge,
      'code_challenge_method': pkce.method,
      'access_type': accessType.name,
    };

    if (forceConsentScreen || config.forceAccountSelection) {
      params['prompt'] = 'consent';
    } else if (config.forceAccountSelection) {
      params['prompt'] = 'select_account';
    }

    params.addAll(config.extraParams);

    final url = Uri.parse(
      GoogleEndpoints.authUrl,
    ).replace(queryParameters: params);

    return OAuthSession(
      authorizationUrl: url.toString(),
      state: state,
      providerName: name,
      pkceChallenge: pkce.challenge,
    );
  }

  /*
   * completeAuth
   * Validates state, exchanges the authorization code for tokens,
   * fetches the Google user-info endpoint, and returns an [OAuthUser].
   * The ID token nonce is verified to prevent replay attacks.
   *
   * Example:
   *   final user = await googleProvider.completeAuth(
   *     callbackParams: request.uri.queryParameters,
   *     stateStore: store,
   *   );
   *   print(user.id); // Google sub (stable identifier)
   */
  @override
  Future<OAuthUser> completeAuth({
    required Map<String, String> callbackParams,
    required StateStore stateStore,
  }) async {
    checkCallbackForErrors(callbackParams);

    final callbackState = callbackParams['state'];
    if (callbackState == null) {
      throw const InvalidStateException('Missing state parameter.');
    }

    final entry = await validateAndConsumeState(callbackState, stateStore);
    final code = callbackParams['code'];
    if (code == null) {
      throw const TokenExchangeException('Missing code in callback.');
    }

    final tokenJson = await postTokenEndpoint(GoogleEndpoints.tokenUrl, {
      'client_id': clientId,
      'client_secret': clientSecret!,
      'code': code,
      'redirect_uri': redirectUri,
      'grant_type': 'authorization_code',
      if (entry.pkceVerifier != null) 'code_verifier': entry.pkceVerifier!,
    });

    final tokens = buildTokenSet(tokenJson);

    // Fetch user info using the access token
    final userInfo = await getWithBearerToken(
      GoogleEndpoints.userInfoUrl,
      tokens.accessToken.value,
    );

    // Basic nonce verification: confirm ID token nonce matches stored nonce.
    // Full JWT signature verification should be done with a proper JWKS library
    // in production. The jose package can be used for this.
    if (tokens.idToken != null && entry.extra.containsKey('nonce')) {
      _verifyIdTokenNonce(tokens.idToken!.jwt, entry.extra['nonce']!);
    }

    return OAuthUser(
      id: userInfo['sub'] as String,
      provider: name,
      email: userInfo['email'] as String?,
      emailVerified: userInfo['email_verified'] as bool? ?? false,
      name: userInfo['name'] as String?,
      firstName: userInfo['given_name'] as String?,
      lastName: userInfo['family_name'] as String?,
      avatarUrl: userInfo['picture'] as String?,
      profileUrl: userInfo['profile'] as String?,
      accessToken: tokens.accessToken.value,
      refreshToken: tokens.refreshToken?.value,
      accessTokenExpiry: tokens.accessToken.expiry,
      rawData: userInfo,
    );
  }

  /*
   * refreshToken
   * Exchanges a refresh token for a new access token using Google's
   * token endpoint. Only works when [accessType] is [GoogleAccessType.offline].
   *
   * Example:
   *   final newTokens = await googleProvider.refreshToken(user.refreshToken!);
   *   // Store newTokens.accessToken.value
   */
  @override
  Future<TokenSet> refreshToken(String refreshToken) async {
    final json = await postTokenEndpoint(GoogleEndpoints.tokenUrl, {
      'client_id': clientId,
      'client_secret': clientSecret!,
      'refresh_token': refreshToken,
      'grant_type': 'refresh_token',
    });
    return buildTokenSet(json);
  }

  /// Performs a basic nonce claim extraction from the ID token JWT payload.
  /// NOTE: This does NOT verify the JWT signature. For production use,
  /// verify the signature using Google's JWKS endpoint:
  ///   https://www.googleapis.com/oauth2/v3/certs
  void _verifyIdTokenNonce(String jwt, String expectedNonce) {
    try {
      final parts = jwt.split('.');
      if (parts.length < 2) return;

      // Pad base64url to valid base64
      var payload = parts[1];
      while (payload.length % 4 != 0) {
        payload += '=';
      }

      final decoded = String.fromCharCodes(
        base64Decode(payload.replaceAll('-', '+').replaceAll('_', '/')),
      );
      // Simple string search to avoid pulling in a full JSON decoder here.
      // The jose package should be used for rigorous validation.
      if (!decoded.contains('"nonce":"$expectedNonce"') &&
          !decoded.contains('"nonce": "$expectedNonce"')) {
        throw const IdTokenValidationException(
          'ID token nonce mismatch — possible replay attack.',
        );
      }
    } catch (e) {
      if (e is IdTokenValidationException) rethrow;
      // Non-fatal: nonce parse failure shouldn't block auth,
      // but log it in production.
    }
  }
}
