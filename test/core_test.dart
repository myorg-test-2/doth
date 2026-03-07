// test/core_test.dart

import 'package:doth/doth.dart';
import 'package:test/test.dart';

void main() {
  group('PkceChallenge', () {
    test('generates a verifier of 128 characters (96 bytes → base64url)', () {
      final pkce = PkceChallenge.generate();
      // 96 bytes base64url-encoded without padding = 128 chars
      expect(pkce.verifier.length, 128);
    });

    test('method is always S256', () {
      expect(PkceChallenge.generate().method, 'S256');
    });

    test('challenge is different from verifier', () {
      final pkce = PkceChallenge.generate();
      expect(pkce.challenge, isNot(pkce.verifier));
    });

    test('two successive challenges are unique', () {
      final a = PkceChallenge.generate();
      final b = PkceChallenge.generate();
      expect(a.verifier, isNot(b.verifier));
      expect(a.challenge, isNot(b.challenge));
    });

    test('verifier contains only base64url characters (no padding)', () {
      final pkce = PkceChallenge.generate();
      expect(pkce.verifier, matches(RegExp(r'^[A-Za-z0-9\-_]+$')));
    });
  });

  group('generateState', () {
    test('produces a non-empty string', () {
      expect(generateState(), isNotEmpty);
    });

    test('two states are unique', () {
      expect(generateState(), isNot(generateState()));
    });
  });

  group('timingSafeEqual', () {
    test('returns true for identical strings', () {
      expect(timingSafeEqual('abc123', 'abc123'), isTrue);
    });

    test('returns false for different strings of same length', () {
      expect(timingSafeEqual('abc123', 'abc124'), isFalse);
    });

    test('returns false for different lengths', () {
      expect(timingSafeEqual('short', 'longer'), isFalse);
    });

    test('empty strings are equal', () {
      expect(timingSafeEqual('', ''), isTrue);
    });
  });

  group('InMemoryStateStore', () {
    late InMemoryStateStore store;

    setUp(() => store = InMemoryStateStore());

    test('saves and consumes an entry', () async {
      final entry = StateEntry(
        providerName: 'github',
        expiry: DateTime.now().add(const Duration(minutes: 5)),
      );
      await store.save('state1', entry);
      final result = await store.consume('state1');
      expect(result, isNotNull);
      expect(result!.providerName, 'github');
    });

    test('returns null for unknown state', () async {
      final result = await store.consume('nonexistent');
      expect(result, isNull);
    });

    test('consume removes entry (replay prevention)', () async {
      final entry = StateEntry(
        providerName: 'google',
        expiry: DateTime.now().add(const Duration(minutes: 5)),
      );
      await store.save('s1', entry);
      await store.consume('s1');
      final second = await store.consume('s1');
      expect(second, isNull);
    });

    test('returns null for expired entry', () async {
      final entry = StateEntry(
        providerName: 'discord',
        expiry: DateTime.now().subtract(
          const Duration(seconds: 1),
        ), // already expired
      );
      await store.save('expired', entry);
      final result = await store.consume('expired');
      expect(result, isNull);
    });

    test('purgeExpired removes only expired entries', () async {
      final good = StateEntry(
        providerName: 'github',
        expiry: DateTime.now().add(const Duration(minutes: 5)),
      );
      final bad = StateEntry(
        providerName: 'github',
        expiry: DateTime.now().subtract(const Duration(seconds: 1)),
      );
      await store.save('good', good);
      await store.save('bad', bad);
      await store.purgeExpired();

      expect(await store.consume('good'), isNotNull);
      expect(await store.consume('bad'), isNull);
    });
  });

  group('Doth registry', () {
    setUp(Doth.clear);

    test('use() registers providers', () {
      Doth.use([
        GitHubProvider(
          clientId: 'id',
          clientSecret: 'secret',
          redirectUri: 'https://example.com/callback',
        ),
      ]);
      expect(Doth.isRegistered('github'), isTrue);
    });

    test('get() returns registered provider', () {
      Doth.use([
        GitHubProvider(
          clientId: 'id',
          clientSecret: 'secret',
          redirectUri: 'https://example.com/callback',
        ),
      ]);
      final p = Doth.get('github');
      expect(p.name, 'github');
    });

    test('get() throws ProviderNotFoundException for unknown provider', () {
      expect(
        () => Doth.get('unknown'),
        throwsA(isA<ProviderNotFoundException>()),
      );
    });

    test('last registration wins for duplicate name', () {
      Doth.use([
        GitHubProvider(
          clientId: 'id1',
          clientSecret: 'secret',
          redirectUri: 'https://a.com/callback',
        ),
      ]);
      Doth.use([
        GitHubProvider(
          clientId: 'id2',
          clientSecret: 'secret',
          redirectUri: 'https://b.com/callback',
        ),
      ]);
      expect(Doth.get('github').clientId, 'id2');
    });

    test('getAll() returns all providers', () {
      Doth.use([
        GitHubProvider(
          clientId: 'id',
          clientSecret: 'secret',
          redirectUri: 'https://example.com/callback',
        ),
        DiscordProvider(
          clientId: 'did',
          clientSecret: 'dsecret',
          redirectUri: 'https://example.com/callback',
        ),
      ]);
      expect(Doth.getAll().length, 2);
    });
  });

  group('OAuthUser', () {
    test('copyWith replaces specified fields', () {
      const user = OAuthUser(
        id: '1',
        provider: 'github',
        accessToken: 'tok',
        rawData: {},
        email: 'old@example.com',
      );
      final updated = user.copyWith(email: 'new@example.com');
      expect(updated.email, 'new@example.com');
      expect(updated.id, '1');
    });
  });

  group('TokenSet', () {
    test('AccessToken.isExpired returns true for past expiry', () {
      final token = AccessToken(
        value: 'tok',
        expiry: DateTime.now().subtract(const Duration(seconds: 1)),
      );
      expect(token.isExpired, isTrue);
    });

    test('AccessToken.isExpired returns false for future expiry', () {
      final token = AccessToken(
        value: 'tok',
        expiry: DateTime.now().add(const Duration(hours: 1)),
      );
      expect(token.isExpired, isFalse);
    });

    test('AccessToken.isExpired returns false when no expiry set', () {
      const token = AccessToken(value: 'tok');
      expect(token.isExpired, isFalse);
    });
  });
}
