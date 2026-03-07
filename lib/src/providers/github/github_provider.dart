// lib/src/providers/github/github_provider.dart

/*
 * GitHubProvider
 * OAuth2 provider for GitHub (https://docs.github.com/en/apps/oauth-apps).
 * Implements Authorization Code flow with PKCE (GitHub supports S256 since 2023).
 *
 * Example:
 *   Doth.use([
 *     GitHubProvider(
 *       clientId: Platform.environment['GITHUB_CLIENT_ID']!,
 *       clientSecret: Platform.environment['GITHUB_CLIENT_SECRET']!,
 *       redirectUri: 'https://yourapp.com/auth/github/callback',
 *       scopes: ['read:user', 'user:email'],
 *     ),
 *   ]);
 */

import 'dart:convert';

import '../../core/provider.dart';

/// GitHub OAuth2 endpoint URLs.
/// Override these to target a GitHub Enterprise instance.
class GitHubEndpoints {
  static String authUrl = 'https://github.com/login/oauth/authorize';
  static String tokenUrl = 'https://github.com/login/oauth/access_token';
  static String profileUrl = 'https://api.github.com/user';
  static String emailsUrl = 'https://api.github.com/user/emails';
}

class GitHubProvider extends OAuthProvider {
  GitHubProvider({
    required super.clientId,
    required super.clientSecret,
    required super.redirectUri,
    List<String> scopes = const ['read:user', 'user:email'],
    super.httpClient,
  }) : super(defaultScopes: scopes, usePkce: true);

  @override
  String get name => 'github';

  @override
  String get displayName => 'GitHub';

  /*
   * beginAuth
   * Generates state + PKCE, then builds the GitHub authorization URL.
   * Returns an [OAuthSession] whose [authorizationUrl] the caller must
   * redirect the user to.
   *
   * Example:
   *   final session = await githubProvider.beginAuth(stateStore: store);
   *   return Response.found(session.authorizationUrl);
   */
  @override
  Future<OAuthSession> beginAuth({
    required StateStore stateStore,
    List<String> scopes = const [],
    AuthConfig config = const AuthConfig(),
  }) async {
    final state = generateState();
    final pkce = PkceChallenge.generate();
    final allScopes = mergeScopes([...scopes, ...config.additionalScopes]);

    await stateStore.save(
      state,
      StateEntry(
        providerName: name,
        expiry: DateTime.now().add(const Duration(minutes: 10)),
        pkceVerifier: pkce.verifier,
      ),
    );

    final url = Uri.parse(GitHubEndpoints.authUrl).replace(
      queryParameters: {
        'client_id': clientId,
        'redirect_uri': redirectUri,
        'scope': allScopes.join(' '),
        'state': state,
        'code_challenge': pkce.challenge,
        'code_challenge_method': pkce.method,
        ...config.extraParams,
      },
    );

    return OAuthSession(
      authorizationUrl: url.toString(),
      state: state,
      providerName: name,
      pkceChallenge: pkce.challenge,
    );
  }

  /*
   * completeAuth
   * Called from your callback handler. Validates state, exchanges the code,
   * fetches the GitHub user profile and verified email, returns [OAuthUser].
   *
   * Example:
   *   final params = request.uri.queryParameters;
   *   final user = await githubProvider.completeAuth(
   *     callbackParams: params, stateStore: store);
   *   print(user.email); // verified GitHub email
   */
  @override
  Future<OAuthUser> completeAuth({
    required Map<String, String> callbackParams,
    required StateStore stateStore,
  }) async {
    checkCallbackForErrors(callbackParams);

    final callbackState = callbackParams['state'];
    if (callbackState == null) {
      throw const InvalidStateException('Missing state parameter in callback.');
    }

    final entry = await validateAndConsumeState(callbackState, stateStore);
    final code = callbackParams['code'];
    if (code == null) {
      throw const TokenExchangeException('Missing code parameter in callback.');
    }

    final tokenJson = await postTokenEndpoint(GitHubEndpoints.tokenUrl, {
      'client_id': clientId,
      'client_secret': clientSecret!,
      'code': code,
      'redirect_uri': redirectUri,
      if (entry.pkceVerifier != null) 'code_verifier': entry.pkceVerifier!,
    });

    final tokens = buildTokenSet(tokenJson);
    final accessToken = tokens.accessToken.value;

    // Fetch profile
    final profile = await getWithBearerToken(
      GitHubEndpoints.profileUrl,
      accessToken,
      extraHeaders: {'X-GitHub-Api-Version': '2022-11-28'},
    );

    // Fetch verified primary email (separate endpoint)
    String? email;
    bool emailVerified = false;
    try {
      final emailsResponse = await httpClient.get(
        Uri.parse(GitHubEndpoints.emailsUrl),
        headers: {
          'Authorization': 'Bearer $accessToken',
          'Accept': 'application/json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      );
      if (emailsResponse.statusCode == 200) {
        final emails = jsonDecode(emailsResponse.body) as List<dynamic>;
        final primary = emails.firstWhere(
          (e) => (e as Map)['primary'] == true,
          orElse: () => null,
        );
        if (primary != null) {
          email = (primary as Map)['email'] as String?;
          emailVerified = (primary['verified'] as bool?) ?? false;
        }
      }
    } catch (_) {
      // Email fetch failure is non-fatal; user.email stays null.
    }

    // Fallback to profile email if no verified primary found
    email ??= profile['email'] as String?;

    return OAuthUser(
      id: profile['id'].toString(),
      provider: name,
      email: email,
      emailVerified: emailVerified,
      name: profile['name'] as String?,
      username: profile['login'] as String?,
      avatarUrl: profile['avatar_url'] as String?,
      profileUrl: profile['html_url'] as String?,
      accessToken: accessToken,
      refreshToken: tokens.refreshToken?.value,
      accessTokenExpiry: tokens.accessToken.expiry,
      rawData: profile,
    );
  }

  /*
   * refreshToken
   * GitHub does not issue refresh tokens for OAuth Apps (only GitHub Apps
   * with expiring tokens). This method will throw [TokenRefreshException]
   * for standard OAuth Apps.
   *
   * Example:
   *   // Only works if you configured a GitHub App with token expiration.
   *   final newTokens = await githubProvider.refreshToken(oldRefreshToken);
   */
  @override
  Future<TokenSet> refreshToken(String refreshToken) async {
    final json = await postTokenEndpoint(GitHubEndpoints.tokenUrl, {
      'client_id': clientId,
      'client_secret': clientSecret!,
      'grant_type': 'refresh_token',
      'refresh_token': refreshToken,
    });
    return buildTokenSet(json);
  }

  @override
  bool get supportsRefresh => false; // Standard OAuth Apps don't get refresh tokens
}
