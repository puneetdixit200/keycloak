package org.keycloak.broker.kubernetes;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class KubernetesJwksEndpointLoaderTest {

    private static final String ISSUER = "https://kubernetes.default.svc.cluster.local";
    private static final String MANAGED_ISSUER = "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE";

    @Test
    public void shouldIncludeTokenWhenTokenIssuerMatchesDiscoveredIssuer() {
        assertTrue(KubernetesJwksEndpointLoader.shouldIncludeToken(tokenWithIssuer(ISSUER), ISSUER));
    }

    @Test
    public void shouldIncludeTokenForManagedIssuerWhenItMatchesDiscovery() {
        assertTrue(KubernetesJwksEndpointLoader.shouldIncludeToken(tokenWithIssuer(MANAGED_ISSUER), MANAGED_ISSUER));
    }

    @Test
    public void shouldNotIncludeTokenWhenTokenIssuerDoesNotMatchDiscoveredIssuer() {
        assertFalse(KubernetesJwksEndpointLoader.shouldIncludeToken(tokenWithIssuer(ISSUER), MANAGED_ISSUER));
    }

    @Test
    public void shouldNotIncludeMalformedToken() {
        assertFalse(KubernetesJwksEndpointLoader.shouldIncludeToken("not-a-jwt", ISSUER));
    }

    @Test
    public void shouldNotIncludeTokenWhenDiscoveredIssuerIsMissing() {
        assertFalse(KubernetesJwksEndpointLoader.shouldIncludeToken(tokenWithIssuer(ISSUER), null));
    }

    private static String tokenWithIssuer(String issuer) {
        String header = base64Url("{\"alg\":\"none\"}");
        String payload = base64Url("{\"iss\":\"" + issuer + "\",\"sub\":\"system:serviceaccount:ns:sa\"}");
        return header + "." + payload + ".";
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
