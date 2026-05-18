package org.keycloak.tests.client.authentication.external;

import java.util.UUID;

import org.keycloak.authentication.authenticators.client.FederatedJWTClientAuthenticator;
import org.keycloak.broker.kubernetes.KubernetesConstants;
import org.keycloak.broker.kubernetes.KubernetesIdentityProviderFactory;
import org.keycloak.common.util.Time;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.oauth.OAuthIdentityProvider;
import org.keycloak.testframework.oauth.OAuthIdentityProviderConfig;
import org.keycloak.testframework.oauth.OAuthIdentityProviderConfigBuilder;
import org.keycloak.testframework.oauth.annotations.InjectOAuthIdentityProvider;
import org.keycloak.testframework.realm.ClientBuilder;
import org.keycloak.testframework.realm.IdentityProviderBuilder;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;

import org.junit.jupiter.api.Test;

@KeycloakIntegrationTest
public class ManagedKubernetesClientAuthTest extends AbstractBaseClientAuthTest {

    static final String INTERNAL_CLIENT_ID = "myclient";
    static final String EXTERNAL_CLIENT_ID = "system:serviceaccount:mynamespace:myserviceaccount";
    static final String IDP_ALIAS = "managed-kubernetes-idp";
    static final String KUBERNETES_API_ISSUER = "http://127.0.0.1:8500/kubernetes";
    static final String MANAGED_ISSUER = "http://127.0.0.1:8500/idp";

    @InjectRealm(config = ManagedKubernetesRealmConfig.class)
    protected ManagedRealm realm;

    @InjectOAuthIdentityProvider(config = ManagedKubernetesIdpConfig.class)
    OAuthIdentityProvider identityProvider;

    public ManagedKubernetesClientAuthTest() {
        super(MANAGED_ISSUER, INTERNAL_CLIENT_ID, EXTERNAL_CLIENT_ID, IDP_ALIAS);
    }

    @Override
    protected OAuthIdentityProvider getIdentityProvider() {
        return identityProvider;
    }

    @Test
    public void testDynamicIssuerResolutionCanBeDisabled() {
        getRealm().updateIdentityProvider(IDP_ALIAS, rep -> {
            rep.getConfig().put(KubernetesConstants.USE_DYNAMIC_ISSUER_RESOLUTION, "false");
        });

        JsonWebToken jwt = createDefaultToken();
        assertFailure(doClientGrant(jwt));
        assertFailure(null, MANAGED_ISSUER, EXTERNAL_CLIENT_ID, jwt.getId(), "client_not_found", events.poll());
    }

    @Override
    protected JsonWebToken createDefaultToken() {
        JsonWebToken token = new JsonWebToken();
        token.id(UUID.randomUUID().toString());
        token.issuer(MANAGED_ISSUER);
        token.audience(oAuthClient.getEndpoints().getIssuer());
        token.nbf((long) Time.currentTime());
        token.exp((long) (Time.currentTime() + 300));
        token.iat((long) (Time.currentTime() - 300));
        token.subject(EXTERNAL_CLIENT_ID);
        return token;
    }

    @Override
    public ManagedRealm getRealm() {
        return realm;
    }

    public static class ManagedKubernetesRealmConfig implements RealmConfig {

        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            realm.identityProviders(
                    IdentityProviderBuilder.create()
                            .providerId(KubernetesIdentityProviderFactory.PROVIDER_ID)
                            .alias(IDP_ALIAS)
                            .attribute(IdentityProviderModel.ISSUER, KUBERNETES_API_ISSUER)
                            .build());

            realm.clients(ClientBuilder.create(INTERNAL_CLIENT_ID)
                    .serviceAccountsEnabled(true)
                    .authenticatorType(FederatedJWTClientAuthenticator.PROVIDER_ID)
                    .attribute(FederatedJWTClientAuthenticator.JWT_CREDENTIAL_ISSUER_KEY, IDP_ALIAS)
                    .attribute(FederatedJWTClientAuthenticator.JWT_CREDENTIAL_SUBJECT_KEY, EXTERNAL_CLIENT_ID));

            return realm;
        }
    }

    public static class ManagedKubernetesIdpConfig implements OAuthIdentityProviderConfig {

        @Override
        public OAuthIdentityProviderConfigBuilder configure(OAuthIdentityProviderConfigBuilder config) {
            return config.kubernetes().kubernetesApiServerIssuer(KUBERNETES_API_ISSUER);
        }
    }
}
