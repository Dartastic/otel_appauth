// Licensed under the Dartastic Pro Software License Agreement.
// Copyright 2025-2026 Mindful Software LLC d/b/a Dartastic.io, All rights reserved.

import 'package:dartastic_opentelemetry/dartastic_opentelemetry.dart';

import 'otel_appauth_suppression.dart';

const _tracerName = 'dartastic_otel_libs_appauth';

Tracer _tracer() => OTel.tracerProvider().getTracer(_tracerName);

class AppAuthResult {
  const AppAuthResult({
    this.issuer,
    this.authorizationEndpoint,
    this.tokenEndpoint,
    this.endSessionEndpoint,
    this.clientId,
    this.redirectUrl,
    this.scopesRequested,
    this.scopesGranted,
    this.tokenType,
    this.accessTokenLength,
    this.idTokenLength,
    this.refreshTokenLength,
    this.expiresInSec,
    this.codeChallengeMethod,
    this.preferEphemeralSession,
    this.grantType,
    this.errorCode,
    this.errorDescription,
    this.statusCode,
  });

  /// OIDC issuer URL.
  final String? issuer;
  final String? authorizationEndpoint;
  final String? tokenEndpoint;
  final String? endSessionEndpoint;

  final String? clientId;
  final String? redirectUrl;

  final List<String>? scopesRequested;
  final List<String>? scopesGranted;

  /// `Bearer`, `MAC`, etc.
  final String? tokenType;

  final int? accessTokenLength;
  final int? idTokenLength;
  final int? refreshTokenLength;

  final int? expiresInSec;

  /// PKCE: `S256` / `plain` / `null`.
  final String? codeChallengeMethod;

  /// ASWebAuthenticationSession `prefersEphemeralWebBrowserSession` on iOS.
  final bool? preferEphemeralSession;

  /// `authorization_code`, `refresh_token`, `client_credentials`,
  /// `password`, `urn:ietf:params:oauth:grant-type:device_code`.
  final String? grantType;

  /// OAuth error code (e.g. `access_denied`, `invalid_grant`,
  /// `invalid_token`, `unauthorized_client`).
  final String? errorCode;
  final String? errorDescription;

  final int? statusCode;
}

class AppAuthCallResult<T> {
  const AppAuthCallResult({required this.value, this.result});
  final T value;
  final AppAuthResult? result;
}

/// Wraps an AppAuth call in a CLIENT span. [operation] is one of
/// `authorize`, `authorizeAndExchangeCode`, `token`, `endSession`,
/// `getDiscoveryDocument`, `refreshToken`.
Future<T> tracedAppAuth<T>({
  required String operation,
  required Future<AppAuthCallResult<T>> Function() invoke,
}) async {
  if (appAuthInstrumentationSuppressed()) {
    final r = await invoke();
    return r.value;
  }
  final m = <String, Object>{
    'rpc.system': 'appauth',
    'rpc.method': operation,
    'appauth.operation': operation,
  };

  final span = _tracer().startSpan(
    'appauth $operation',
    kind: SpanKind.client,
    attributes: OTel.attributesFromMap(m),
  );
  try {
    final r = await invoke();
    if (r.result != null) {
      final res = r.result!;
      final extras = <Attribute<Object>>[];
      if (res.issuer != null) {
        extras.add(OTel.attributeString('appauth.issuer', res.issuer!));
      }
      if (res.authorizationEndpoint != null) {
        extras.add(OTel.attributeString(
          'appauth.authorization_endpoint',
          res.authorizationEndpoint!,
        ));
      }
      if (res.tokenEndpoint != null) {
        extras.add(OTel.attributeString(
          'appauth.token_endpoint',
          res.tokenEndpoint!,
        ));
      }
      if (res.endSessionEndpoint != null) {
        extras.add(OTel.attributeString(
          'appauth.end_session_endpoint',
          res.endSessionEndpoint!,
        ));
      }
      if (res.clientId != null) {
        extras.add(OTel.attributeString('appauth.client_id', res.clientId!));
      }
      if (res.redirectUrl != null) {
        extras.add(OTel.attributeString(
          'appauth.redirect_url',
          res.redirectUrl!,
        ));
      }
      if (res.scopesRequested != null) {
        extras.add(OTel.attributeStringList(
          'appauth.scopes.requested',
          res.scopesRequested!,
        ));
      }
      if (res.scopesGranted != null) {
        extras.add(OTel.attributeStringList(
          'appauth.scopes.granted',
          res.scopesGranted!,
        ));
      }
      if (res.tokenType != null) {
        extras.add(OTel.attributeString(
          'appauth.token.type',
          res.tokenType!,
        ));
      }
      if (res.accessTokenLength != null) {
        extras.add(OTel.attributeInt(
          'appauth.access_token.length',
          res.accessTokenLength!,
        ));
      }
      if (res.idTokenLength != null) {
        extras.add(OTel.attributeInt(
          'appauth.id_token.length',
          res.idTokenLength!,
        ));
      }
      if (res.refreshTokenLength != null) {
        extras.add(OTel.attributeInt(
          'appauth.refresh_token.length',
          res.refreshTokenLength!,
        ));
      }
      if (res.expiresInSec != null) {
        extras.add(OTel.attributeInt(
          'appauth.expires_in_sec',
          res.expiresInSec!,
        ));
      }
      if (res.codeChallengeMethod != null) {
        extras.add(OTel.attributeString(
          'appauth.code_challenge_method',
          res.codeChallengeMethod!,
        ));
      }
      if (res.preferEphemeralSession != null) {
        extras.add(OTel.attributeBool(
          'appauth.prefer_ephemeral_session',
          res.preferEphemeralSession!,
        ));
      }
      if (res.grantType != null) {
        extras.add(OTel.attributeString(
          'appauth.grant_type',
          res.grantType!,
        ));
      }
      if (res.errorCode != null) {
        extras.add(OTel.attributeString(
          'appauth.error.code',
          res.errorCode!,
        ));
        if (res.errorCode != 'access_denied') {
          span.setStatus(
            SpanStatusCode.Error,
            'AppAuth ${res.errorCode}',
          );
        }
      }
      if (res.errorDescription != null) {
        extras.add(OTel.attributeString(
          'appauth.error.description',
          res.errorDescription!,
        ));
      }
      if (res.statusCode != null) {
        extras.add(OTel.attributeInt(
          'http.response.status_code',
          res.statusCode!,
        ));
        if (res.statusCode! >= 400) {
          span.setStatus(
            SpanStatusCode.Error,
            'AppAuth HTTP ${res.statusCode}',
          );
        }
      }
      if (extras.isNotEmpty) span.addAttributes(OTel.attributes(extras));
    }
    return r.value;
  } catch (e, st) {
    span.addAttributes(OTel.attributes([
      OTel.attributeString(
        ErrorResource.errorType.key,
        e.runtimeType.toString(),
      ),
    ]));
    span.recordException(e, stackTrace: st);
    span.setStatus(SpanStatusCode.Error, e.toString());
    rethrow;
  } finally {
    span.end();
  }
}
