package org.keycloak.broker.kubernetes;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.keycloak.common.enums.SslRequired;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpRequest;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.Strings;

import static org.keycloak.broker.kubernetes.KubernetesConstants.SERVICE_ACCOUNT_TOKEN_PATH;
import static org.keycloak.common.util.UriUtils.checkUrl;

final class KubernetesIssuerResolver {

    private KubernetesIssuerResolver() {
    }

    static String resolveIssuer(KeycloakSession session, KubernetesIdentityProviderConfig config, SslRequired sslRequired) throws Exception {
        String configuredIssuer = config.getIssuer();
        if (!config.isUseDynamicIssuerResolution()) {
            checkUrl(sslRequired, configuredIssuer, "Issuer");
            return configuredIssuer;
        }

        String token = config.isIncludeServiceAccountToken() ? readServiceAccountToken() : null;
        return discoverIssuer(SimpleHttp.create(session), configuredIssuer, token, sslRequired);
    }

    static String discoverIssuer(SimpleHttp simpleHttp, String configuredIssuer, String token, SslRequired sslRequired) throws Exception {
        OIDCConfigurationRepresentation openIdConfiguration = loadOpenIdConfiguration(simpleHttp, configuredIssuer, token, sslRequired);
        String discoveredIssuer = openIdConfiguration.getIssuer();
        if (Strings.isEmpty(discoveredIssuer)) {
            throw new IllegalStateException("OIDC discovery at " + getWellKnownEndpoint(configuredIssuer) + " returned no issuer");
        }

        checkUrl(sslRequired, discoveredIssuer, "Issuer");
        return discoveredIssuer;
    }

    static OIDCConfigurationRepresentation loadOpenIdConfiguration(SimpleHttp simpleHttp, String issuer, String token, SslRequired sslRequired) throws Exception {
        checkUrl(sslRequired, issuer, "Issuer");

        String wellKnownEndpoint = getWellKnownEndpoint(issuer);
        SimpleHttpRequest request = simpleHttp.doGet(wellKnownEndpoint).acceptJson();
        if (!Strings.isEmpty(token)) {
            request.auth(token);
        }

        return executeAndParse(request, wellKnownEndpoint, OIDCConfigurationRepresentation.class);
    }

    static <T> T executeAndParse(SimpleHttpRequest request, String url, Class<T> type) throws Exception {
        try (SimpleHttpResponse response = request.asResponse()) {
            int status = response.getStatus();
            if (status != 200) {
                throw new IllegalStateException("Request to " + url + " returned HTTP " + status);
            }
            return JsonSerialization.readValue(response.asString(), type);
        }
    }

    static String getWellKnownEndpoint(String issuer) {
        return issuer.endsWith("/") ? issuer + ".well-known/openid-configuration" : issuer + "/.well-known/openid-configuration";
    }

    static String readServiceAccountToken() {
        try {
            Path path = Path.of(SERVICE_ACCOUNT_TOKEN_PATH);
            if (!Files.exists(path)) {
                return null;
            }
            return Files.readString(path, StandardCharsets.UTF_8).trim();
        } catch (Exception e) {
            return null;
        }
    }
}
