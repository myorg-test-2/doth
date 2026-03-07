// example/shelf_example.dart
//
// A minimal shelf server demonstrating doth with GitHub and Google.
//
// Run with:
//   export GITHUB_CLIENT_ID=your_id
//   export GITHUB_CLIENT_SECRET=your_secret
//   export GOOGLE_CLIENT_ID=your_id
//   export GOOGLE_CLIENT_SECRET=your_secret
//   dart run example/shelf_example.dart

import 'dart:io';

import 'package:doth/doth.dart';
import 'package:doth/src/adapters/shelf_adapter.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:shelf_router/shelf_router.dart';

void main() async {
  // ── 1. Configure providers ─────────────────────────────────────────────────
  Doth.use([
    GitHubProvider(
      clientId: Platform.environment['GITHUB_CLIENT_ID'] ?? '',
      clientSecret: Platform.environment['GITHUB_CLIENT_SECRET'] ?? '',
      redirectUri: 'http://localhost:8080/auth/github/callback',
      scopes: ['read:user', 'user:email'],
    ),
    GoogleProvider(
      clientId: Platform.environment['GOOGLE_CLIENT_ID'] ?? '',
      clientSecret: Platform.environment['GOOGLE_CLIENT_SECRET'] ?? '',
      redirectUri: 'http://localhost:8080/auth/google/callback',
      accessType: GoogleAccessType.offline,
    ),
  ]);

  // ── 2. Define routes ───────────────────────────────────────────────────────
  final router = Router()
    // Home page — shows login links
    ..get('/', _homeHandler)
    // Begin OAuth flow — redirects user to provider
    ..get('/auth/<provider>', ShelfAdapter.beginAuthHandler)
    // Callback — provider redirects back here with ?code=&state=
    ..get(
      '/auth/<provider>/callback',
      ShelfAdapter.callbackHandler(onSuccess: _onSuccess, onError: _onError),
    )
    // Apple requires a POST callback (form_post response_mode)
    ..post(
      '/auth/apple/callback',
      ShelfAdapter.postCallbackHandler(
        onSuccess: _onSuccess,
        onError: _onError,
      ),
    );

  // ── 3. Start server ────────────────────────────────────────────────────────
  final handler = Pipeline()
      .addMiddleware(logRequests())
      .addHandler(router.call);

  final server = await io.serve(handler, 'localhost', 8080);
  print('doth example server running at http://localhost:${server.port}');
  print('Visit http://localhost:${server.port}/ to start');
}

// ── Handlers ──────────────────────────────────────────────────────────────────

Response _homeHandler(Request _) {
  final providers = Doth.getAll()
      .map((p) => '<li><a href="/auth/${p.name}">${p.displayName}</a></li>')
      .join('\n');

  return Response.ok(
    '''
    <!DOCTYPE html>
    <html>
      <body>
        <h1>doth — Social Login Demo</h1>
        <p>Sign in with:</p>
        <ul>$providers</ul>
      </body>
    </html>
    ''',
    headers: {'content-type': 'text/html'},
  );
}

Future<Response> _onSuccess(OAuthUser user, Request request) async {
  // In a real app: create/update a DB record, set a session cookie.
  return Response.ok(
    '''
    <!DOCTYPE html>
    <html>
      <body>
        <h1>Welcome, ${user.name ?? user.username ?? 'user'}!</h1>
        <ul>
          <li>Provider: ${user.provider}</li>
          <li>ID: ${user.id}</li>
          <li>Email: ${user.email ?? 'not provided'}</li>
          <li>Verified: ${user.emailVerified}</li>
          <li>Avatar: ${user.avatarUrl != null ? '<img src="${user.avatarUrl}" width="64"/>' : 'none'}</li>
        </ul>
        <a href="/">Sign in with a different provider</a>
      </body>
    </html>
    ''',
    headers: {'content-type': 'text/html'},
  );
}

Future<Response> _onError(OAuthException error, Request request) async {
  final statusCode = switch (error) {
    InvalidStateException _ => 403,
    ProviderErrorException _ => 400,
    ProviderNotFoundException _ => 404,
    _ => 500,
  };

  return Response(statusCode, body: 'Authentication failed: ${error.message}');
}
