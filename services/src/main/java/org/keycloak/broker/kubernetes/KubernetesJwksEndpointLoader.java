package org.keycloak.broker.kubernetes;

import org.keycloak.common.enums.SslRequired;
import org.keycloak.crypto.PublicKeysWrapper;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.keys.PublicKeyLoader;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.Strings;

import org.apache.http.HttpHeaders;
import org.jboss.logging.Logger;

import static org.keycloak.common.util.UriUtils.checkUrl;

public class KubernetesJwksEndpointLoader implements PublicKeyLoader {

    private static final Logger logger = Logger.getLogger(KubernetesJwksEndpointLoader.class);

    private final KeycloakSession session;
    private final String issuer;
    private final boolean includeServiceAccountToken;
    private final SslRequired sslRequired;

    public KubernetesJwksEndpointLoader(KeycloakSession session, String issuer) {
        this(session, issuer, true, SslRequired.EXTERNAL);
    }

    public KubernetesJwksEndpointLoader(KeycloakSession session, String issuer, boolean includeServiceAccountToken, SslRequired sslRequired) {
        this.session = session;
        this.issuer = issuer;
        this.includeServiceAccountToken = includeServiceAccountToken;
        this.sslRequired = sslRequired;
    }

    @Override
    public PublicKeysWrapper loadKeys() throws Exception {
        SimpleHttp simpleHttp = SimpleHttp.create(session);

        String token = includeServiceAccountToken ? KubernetesIssuerResolver.readServiceAccountToken() : null;
        String wellKnownEndpoint = KubernetesIssuerResolver.getWellKnownEndpoint(issuer);

        SimpleHttpRequest wellKnownReqest = simpleHttp.doGet(wellKnownEndpoint).acceptJson();
        if (token != null && shouldIncludeToken(token, issuer)) {
            wellKnownReqest.auth(token);
        }
        OIDCConfigurationRepresentation openIdConfiguration = KubernetesIssuerResolver.executeAndParse(wellKnownReqest, wellKnownEndpoint, OIDCConfigurationRepresentation.class);

        String discoveredIssuer = openIdConfiguration.getIssuer();
        if (Strings.isEmpty(discoveredIssuer)) {
            throw new IllegalStateException("OIDC discovery at " + wellKnownEndpoint + " returned no issuer");
        }
        if (!issuer.equals(discoveredIssuer)) {
            throw new IllegalStateException("OIDC discovery at " + wellKnownEndpoint + " returned issuer '" + discoveredIssuer + "' but expected '" + issuer + "'");
        }

        String jwksUri = openIdConfiguration.getJwksUri();
        if (Strings.isEmpty(jwksUri)) {
            throw new IllegalStateException("OIDC discovery at " + wellKnownEndpoint + " returned no jwks_uri");
        }
        checkUrl(sslRequired, jwksUri, "jwks_uri");

        SimpleHttpRequest jwksRequest = simpleHttp.doGet(jwksUri).header(HttpHeaders.ACCEPT, "application/jwk-set+json");
        if (token != null && shouldIncludeToken(token, discoveredIssuer)) {
            jwksRequest.auth(token);
        }

        JSONWebKeySet jwks = KubernetesIssuerResolver.executeAndParse(jwksRequest, jwksUri, JSONWebKeySet.class);
        return JWKSUtils.getKeyWrappersForUse(jwks, JWK.Use.SIG);
    }

    static boolean shouldIncludeToken(String token, String discoveredIssuer) {
        if (Strings.isEmpty(discoveredIssuer)) {
            return false;
        }

        try {
            JsonWebToken jwt = new JWSInput(token).readJsonContent(JsonWebToken.class);
            if (discoveredIssuer.equals(jwt.getIssuer())) {
                return true;
            }
        } catch (Exception e) {
            logger.debug("Failed to parse service account token issuer", e);
        }
        return false;
    }
}
