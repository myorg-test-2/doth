/*
* OAuthUser
* A normalized representation of a user returned by an OAuth provider.
* Raw provider-specific fields are available via [rawData]
*
* Example:
*   final user = await provider.fetchUser(session);
*   print(user.email);    // 'bob@example.com'
*   print(user.rawData['login'])  // Github-specific username
*/

/// Normalized user returned after a completed OAuth flow.
///
/// Every provider populates the subset of field it supports.
/// Fields unsupported by a particular provider are `null`.
/// Always check[rawData] for provider-specific attributes.
class OAuthUser {
  /// Unique provider-scoped identifier (e.g. Google sub, Github userid).
  final String id;

  /// The provider name that authenticated this user (e.g. 'google', 'apple', 'github').
  final String provider;

  /// Primary email address, if the provider returns one.
  final String? email;

  /// Has the email been verified by the provider?
  final bool emailVerified;

  /// Display name or full name
  final String? name;

  /// First name, if the provider returns it seperately.
  final String? firstName;

  /// Last name,if the provider returns it seperately.
  final String? lastName;

  /// URL to the user's profile pciture/avatar.
  final String? avatarUrl;

  /// Provider-issued username / handle (e.g. Github login).
  final String? username;

  /// URL to the user's public profile page.
  final String? profileUrl;

  /// The access token issued for this user.
  final String accessToken;

  /// The refresh token, if one was granted.
  final String? refreshToken;

  /// When the access token expires, if known.
  final DateTime? accessTokenExpiry;

  /// Complete raw JSON map returned by the provider's user-info endpoint.
  /// Use this for attributes not modelled above.
  final Map<String, dynamic> rawData;

  const OAuthUser({
    required this.id,
    required this.provider,
    required this.accessToken,
    required this.rawData,
    this.email,
    this.emailVerified = false,
    this.name,
    this.firstName,
    this.lastName,
    this.avatarUrl,
    this.username,
    this.profileUrl,
    this.refreshToken,
    this.accessTokenExpiry,
  });

  @override
  String toString() =>
      'OAuthUser(id: $id, provider: $provider, email: $email, name: $name)';

  /// Returns a copy with selected fields replaced.
  OAuthUser copyWith({
    String? id,
    String? provider,
    String? email,
    bool? emailVerified,
    String? name,
    String? firstName,
    String? lastName,
    String? avatarUrl,
    String? username,
    String? profileUrl,
    String? accessToken,
    String? refreshToken,
    DateTime? accessTokenExpiry,
    Map<String, dynamic>? rawData,
  }) {
    return OAuthUser(
      id: id ?? this.id,
      provider: provider ?? this.provider,
      email: email ?? this.email,
      emailVerified: emailVerified ?? this.emailVerified,
      name: name ?? this.name,
      firstName: firstName ?? this.firstName,
      lastName: lastName ?? this.lastName,
      avatarUrl: avatarUrl ?? this.avatarUrl,
      username: username ?? this.username,
      profileUrl: profileUrl ?? this.profileUrl,
      accessToken: accessToken ?? this.accessToken,
      refreshToken: refreshToken ?? this.refreshToken,
      accessTokenExpiry: accessTokenExpiry ?? this.accessTokenExpiry,
      rawData: rawData ?? this.rawData,
    );
  }
}
