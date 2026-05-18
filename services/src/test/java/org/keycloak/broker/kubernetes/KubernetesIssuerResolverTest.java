package org.keycloak.broker.kubernetes;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

import org.keycloak.common.enums.SslRequired;
import org.keycloak.http.simple.SimpleHttp;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class KubernetesIssuerResolverTest {

    private HttpServer server;
    private CloseableHttpClient httpClient;
    private String baseUrl;

    @Before
    public void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
        httpClient = HttpClients.createDefault();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @After
    public void tearDown() throws Exception {
        if (server != null) {
            server.stop(0);
        }
        if (httpClient != null) {
            httpClient.close();
        }
    }

    @Test
    public void discoversIssuerFromKubernetesOpenIdConfiguration() throws Exception {
        String discoveredIssuer = baseUrl + "/idp";
        wellKnown("/kubernetes", 200, "{\"issuer\":\"" + discoveredIssuer + "\",\"jwks_uri\":\"" + discoveredIssuer + "/jwks\"}");

        String result = KubernetesIssuerResolver.discoverIssuer(SimpleHttp.create(httpClient), baseUrl + "/kubernetes", null, SslRequired.EXTERNAL);

        assertEquals(discoveredIssuer, result);
    }

    @Test
    public void rejectsNon200OpenIdConfigurationResponse() throws Exception {
        wellKnown("/kubernetes", 404, "{}");

        try {
            KubernetesIssuerResolver.discoverIssuer(SimpleHttp.create(httpClient), baseUrl + "/kubernetes", null, SslRequired.EXTERNAL);
            fail("Expected non-200 discovery response to be rejected");
        } catch (IllegalStateException e) {
            assertTrue(e.getMessage().contains("HTTP 404"));
        }
    }

    @Test
    public void rejectsOpenIdConfigurationWithoutIssuer() throws Exception {
        wellKnown("/kubernetes", 200, "{\"jwks_uri\":\"" + baseUrl + "/idp/jwks\"}");

        try {
            KubernetesIssuerResolver.discoverIssuer(SimpleHttp.create(httpClient), baseUrl + "/kubernetes", null, SslRequired.EXTERNAL);
            fail("Expected discovery response without issuer to be rejected");
        } catch (IllegalStateException e) {
            assertTrue(e.getMessage().contains("issuer"));
        }
    }

    @Test
    public void rejectsInsecureExternalDiscoveredIssuer() throws Exception {
        wellKnown("/kubernetes", 200, "{\"issuer\":\"http://issuer.example.com\",\"jwks_uri\":\"http://issuer.example.com/jwks\"}");

        try {
            KubernetesIssuerResolver.discoverIssuer(SimpleHttp.create(httpClient), baseUrl + "/kubernetes", null, SslRequired.EXTERNAL);
            fail("Expected insecure external issuer to be rejected");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("requires secure connections"));
        }
    }

    private void wellKnown(String issuerPath, int status, String body) {
        server.createContext(issuerPath + "/.well-known/openid-configuration", exchange -> send(exchange, status, body));
    }

    private static void send(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(bytes);
        }
    }
}
