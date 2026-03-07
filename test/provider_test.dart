// test/provider_test.dart
// Tests for provider beginAuth — no network calls required.

import 'package:doth/doth.dart';
import 'package:test/test.dart';

void main() {
  late InMemoryStateStore store;

  setUp(() => store = InMemoryStateStore());

  group('GitHubProvider.beginAuth', () {
    late GitHubProvider provider;

    setUp(() {
      provider = GitHubProvider(
        clientId: 'gh_client_id',
        clientSecret: 'gh_secret',
        redirectUri: 'https://example.com/auth/github/callback',
      );
    });

    test('returns a session with an authorization URL', () async {
      final session = await provider.beginAuth(stateStore: store);
      expect(
        session.authorizationUrl,
        contains('github.com/login/oauth/authorize'),
      );
      expect(session.authorizationUrl, contains('gh_client_id'));
      expect(session.providerName, 'github');
    });

    test('authorization URL includes PKCE challenge', () async {
      final session = await provider.beginAuth(stateStore: store);
      expect(session.authorizationUrl, contains('code_challenge='));
      expect(session.authorizationUrl, contains('code_challenge_method=S256'));
    });

    test('state is persisted in store', () async {
      final session = await provider.beginAuth(stateStore: store);
      final entry = await store.consume(session.state);
      expect(entry, isNotNull);
      expect(entry!.pkceVerifier, isNotNull);
    });

    test('custom scopes are included in URL', () async {
      final session = await provider.beginAuth(
        stateStore: store,
        scopes: ['repo'],
      );
      expect(session.authorizationUrl, contains('repo'));
    });

    test('two sessions have different states', () async {
      final s1 = await provider.beginAuth(stateStore: store);
      final s2 = await provider.beginAuth(stateStore: store);
      expect(s1.state, isNot(s2.state));
    });
  });

  group('GoogleProvider.beginAuth', () {
    late GoogleProvider provider;

    setUp(() {
      provider = GoogleProvider(
        clientId: 'google_id',
        clientSecret: 'google_secret',
        redirectUri: 'https://example.com/auth/google/callback',
      );
    });

    test('authorization URL targets accounts.google.com', () async {
      final session = await provider.beginAuth(stateStore: store);
      expect(
        session.authorizationUrl,
        contains('accounts.google.com/o/oauth2/v2/auth'),
      );
    });

    test('includes nonce in state store extra', () async {
      final session = await provider.beginAuth(stateStore: store);
      final entry = await store.consume(session.state);
      expect(entry!.extra.containsKey('nonce'), isTrue);
      expect(entry.extra['nonce'], isNotEmpty);
    });

    test('includes access_type=offline by default', () async {
      final session = await provider.beginAuth(stateStore: store);
      expect(session.authorizationUrl, contains('access_type=offline'));
    });
  });

  group('DiscordProvider.beginAuth', () {
    test('URL includes discord.com domain', () async {
      final provider = DiscordProvider(
        clientId: 'dc_id',
        clientSecret: 'dc_secret',
        redirectUri: 'https://example.com/auth/discord/callback',
      );
      final session = await provider.beginAuth(stateStore: store);
      expect(
        session.authorizationUrl,
        contains('discord.com/api/oauth2/authorize'),
      );
    });
  });

  group('MicrosoftProvider.beginAuth', () {
    test('URL uses common tenant by default', () async {
      final provider = MicrosoftProvider(
        clientId: 'ms_id',
        clientSecret: 'ms_secret',
        redirectUri: 'https://example.com/auth/microsoft/callback',
      );
      final session = await provider.beginAuth(stateStore: store);
      expect(
        session.authorizationUrl,
        contains('login.microsoftonline.com/common'),
      );
    });

    test('specific tenant ID is used when provided', () async {
      final provider = MicrosoftProvider(
        clientId: 'ms_id',
        clientSecret: 'ms_secret',
        redirectUri: 'https://example.com/auth/microsoft/callback',
        tenantId: 'my-tenant-id',
      );
      final session = await provider.beginAuth(stateStore: store);
      expect(
        session.authorizationUrl,
        contains('login.microsoftonline.com/my-tenant-id'),
      );
    });
  });

  group('AppleProvider.beginAuth', () {
    test('authorization URL targets appleid.apple.com', () async {
      final provider = AppleProvider(
        clientId: 'com.example.app',
        teamId: 'TEAM1234',
        keyId: 'KEY1234',
        privateKeyPem: '---fake-pem---',
        redirectUri: 'https://example.com/auth/apple/callback',
      );
      final session = await provider.beginAuth(stateStore: store);
      expect(
        session.authorizationUrl,
        contains('appleid.apple.com/auth/authorize'),
      );
      expect(session.authorizationUrl, contains('form_post'));
    });
  });

  group('validateAndConsumeState', () {
    test('throws InvalidStateException when state not in store', () async {
      final provider = GitHubProvider(
        clientId: 'id',
        clientSecret: 'secret',
        redirectUri: 'https://example.com/callback',
      );
      expect(
        () => provider.validateAndConsumeState('bad_state', store),
        throwsA(isA<InvalidStateException>()),
      );
    });

    test(
      'throws InvalidStateException when state belongs to different provider',
      () async {
        await store.save(
          'cross_state',
          StateEntry(
            providerName: 'google',
            expiry: DateTime.now().add(const Duration(minutes: 5)),
          ),
        );
        final githubProvider = GitHubProvider(
          clientId: 'id',
          clientSecret: 'secret',
          redirectUri: 'https://example.com/callback',
        );
        expect(
          () => githubProvider.validateAndConsumeState('cross_state', store),
          throwsA(isA<InvalidStateException>()),
        );
      },
    );
  });

  group('checkCallbackForErrors', () {
    late GitHubProvider provider;

    setUp(() {
      provider = GitHubProvider(
        clientId: 'id',
        clientSecret: 'secret',
        redirectUri: 'https://example.com/callback',
      );
    });

    test('throws ProviderErrorException on access_denied', () {
      expect(
        () => provider.checkCallbackForErrors({
          'error': 'access_denied',
          'error_description': 'User denied access',
        }),
        throwsA(isA<ProviderErrorException>()),
      );
    });

    test('does not throw when no error present', () {
      expect(
        () => provider.checkCallbackForErrors({'code': 'abc', 'state': 'xyz'}),
        returnsNormally,
      );
    });
  });
}
