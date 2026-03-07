/*
* OAuthToken (sealed)
* A sealed class modelling OAuth tokens.
* Dart 3 sealed classes allow exhaustive pattern-matching at call sites.
*
* Example:
*   final result = switch (token) {
*     AccessToken t => 'access: ${t.value}',
*     RefreshToken t => 'refresh: ${t.value}',
*     IdToken t => 'id: ${t.jwt}',
*   };
*/

/// Base sealed token type. Use pattern matching to discriminate subtypes.
sealed class OAuthToken {
  /// The raw token string.
  final String value;

  /// When this token expires, or `null` if not reported.
  final DateTime? expiry;

  const OAuthToken({required this.value, this.expiry});

  /// Returns true if the token has an [expiry] in the past.
  bool get isExpired {
    if (expiry == null) return false;
    return DateTime.now().isAfter(expiry!);
  }
}

/// A short-lived bearer token used to authenticate API requests.
final class AccessToken extends OAuthToken {
  /// OAuth scopes granted along with this token.
  final List<String> scopes;

  const AccessToken({
    required super.value,
    super.expiry,
    this.scopes = const [],
  });
}

/// A long-lived token used to obtain a new [AccessToken] without
/// requiring the user to re-authenticate.
final class RefreshToken extends OAuthToken {
  const RefreshToken({required super.value, super.expiry});
}

/// An OpenID Coonect ID token (JWT) containing identity claims.
/// Present only when the provider supports OIDC (Google, Apple, Microsoft).
final class IdToken extends OAuthToken {
  /// The raw JWT string (same as [value], exposed for clarity).
  String get jwt => value;

  const IdToken({required super.value, super.expiry});
}

/// A set of tokens returned together after a successful token exchange.
class TokenSet {
  final AccessToken accessToken;
  final RefreshToken? refreshToken;
  final IdToken? idToken;

  const TokenSet({required this.accessToken, this.refreshToken, this.idToken});
}
