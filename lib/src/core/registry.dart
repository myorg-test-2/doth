/*
 * Doth
 * Central registry for OAuth providers and shared configuration.
 * Modelled after goth.UseProviders() / goth.GetProvider().
 *
 * Example:
 *   Doth.use([
 *     GitHubProvider(clientId: '...', clientSecret: '...', redirectUri: '...'),
 *     GoogleProvider(clientId: '...', clientSecret: '...', redirectUri: '...'),
 *   ]);
 *
 *   final provider = Doth.get('github');
 *   final session = await provider.beginAuth(stateStore: Doth.stateStore);
 */

import 'provider.dart';

/// Thread-safe global registry for [OAuthProvider] instances.
class Doth {
  Doth._();

  static final _providers = <String, OAuthProvider>{};

  /// The state store used by all providers unless overridden per-request.
  /// Default is [InMemoryStateStore]. Replace with a distributed store
  /// before deploying in multi-instance environments.
  static StateStore stateStore = InMemoryStateStore();

  /*
   * use
   * Registers one or more providers. If a provider with the same [name]
   * already exists it is replaced by the newest registration (last-write-wins).
   *
   * Example:
   *   Doth.use([
   *     GitHubProvider(clientId: env['GITHUB_ID']!, ...),
   *     GoogleProvider(clientId: env['GOOGLE_ID']!, ...),
   *   ]);
   */
  static void use(List<OAuthProvider> providers) {
    for (final p in providers) {
      _providers[p.name] = p;
    }
  }

  /*
   * get
   * Retrieves a registered provider by name.
   * Throws [ProviderNotFoundException] if the provider was never registered.
   *
   * Example:
   *   final github = Doth.get('github');
   */
  static OAuthProvider get(String name) {
    final provider = _providers[name.toLowerCase()];
    if (provider == null) throw ProviderNotFoundException(name);
    return provider;
  }

  /*
   * getAll
   * Returns an unmodifiable view of all registered providers.
   *
   * Example:
   *   final names = Doth.getAll().map((p) => p.displayName).toList();
   */
  static List<OAuthProvider> getAll() => List.unmodifiable(_providers.values);

  /*
   * clear
   * Removes all registered providers. Primarily useful in tests.
   *
   * Example:
   *   tearDown(Doth.clear);
   */
  static void clear() => _providers.clear();

  /*
   * isRegistered
   * Returns true if a provider with [name] has been registered.
   *
   * Example:
   *   if (!Doth.isRegistered('apple')) {
   *     throw StateError('Apple Sign-In not configured');
   *   }
   */
  static bool isRegistered(String name) =>
      _providers.containsKey(name.toLowerCase());
}
