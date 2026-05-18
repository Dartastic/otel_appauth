// Licensed under the Dartastic Pro Software License Agreement.
// Copyright 2025-2026 Mindful Software LLC d/b/a Dartastic.io, All rights reserved.

import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';
import 'package:dartastic_opentelemetry/testing.dart';
import 'package:otel_appauth/otel_appauth.dart';
import 'package:test/test.dart';

void main() {
  late TestHarness harness;
  late InMemorySpanExporter spans;

  setUpAll(() async {
    harness =
        await maybeInitializeOtelForTest(serviceName: 'otel_appauth-test');
    spans = harness.spans;
  });

  setUp(() => harness.clear());

  Map<String, Object> attrsOf(Span s) =>
      {for (final a in s.attributes.toList()) a.key: a.value};

  test('authorizeAndExchangeCode records issuer + grant + PKCE', () async {
    await tracedAppAuth<String>(
      operation: 'authorizeAndExchangeCode',
      invoke: () async => const AppAuthCallResult(
        value: 'ok',
        result: AppAuthResult(
          issuer: 'https://login.example.com',
          clientId: 'app_1',
          grantType: 'authorization_code',
          codeChallengeMethod: 'S256',
          tokenType: 'Bearer',
          scopesRequested: ['openid', 'profile', 'email'],
          scopesGranted: ['openid', 'profile', 'email'],
          expiresInSec: 3600,
        ),
      ),
    );
    final a =
        attrsOf(spans.findSpanByName('appauth authorizeAndExchangeCode')!);
    expect(a['appauth.issuer'], 'https://login.example.com');
    expect(a['appauth.code_challenge_method'], 'S256');
    expect(a['appauth.grant_type'], 'authorization_code');
  });

  test('invalid_grant error sets span error', () async {
    await tracedAppAuth<String>(
      operation: 'token',
      invoke: () async => const AppAuthCallResult(
        value: 'ok',
        result: AppAuthResult(errorCode: 'invalid_grant', statusCode: 400),
      ),
    );
    expect(
      spans.findSpanByName('appauth token')!.status,
      SpanStatusCode.Error,
    );
  });

  test('access_denied does NOT set span error', () async {
    await tracedAppAuth<String>(
      operation: 'authorize',
      invoke: () async => const AppAuthCallResult(
        value: 'ok',
        result: AppAuthResult(errorCode: 'access_denied'),
      ),
    );
    expect(
      spans.findSpanByName('appauth authorize')!.status,
      isNot(SpanStatusCode.Error),
    );
  });

  test('suppression skips spans', () async {
    await runWithoutAppAuthInstrumentationAsync(() async {
      await tracedAppAuth<String>(
        operation: 'endSession',
        invoke: () async => const AppAuthCallResult(value: 'v'),
      );
    });
    expect(spans.findSpansStartingWith('appauth '), isEmpty);
  });
}
