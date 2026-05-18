package org.keycloak.broker.kubernetes;

import org.keycloak.models.IdentityProviderModel;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class KubernetesIdentityProviderConfigTest {

    @Test
    public void dynamicIssuerResolutionDefaultsToEnabled() {
        KubernetesIdentityProviderConfig config = new KubernetesIdentityProviderConfig(new IdentityProviderModel());

        assertTrue(config.isUseDynamicIssuerResolution());
    }

    @Test
    public void serviceAccountTokenForwardingDefaultsToDisabled() {
        KubernetesIdentityProviderConfig config = new KubernetesIdentityProviderConfig(new IdentityProviderModel());

        assertFalse(config.isIncludeServiceAccountToken());
    }

    @Test
    public void readsConfiguredDynamicIssuerResolutionFlag() {
        IdentityProviderModel model = new IdentityProviderModel();
        model.getConfig().put(KubernetesConstants.USE_DYNAMIC_ISSUER_RESOLUTION, "false");

        KubernetesIdentityProviderConfig config = new KubernetesIdentityProviderConfig(model);

        assertFalse(config.isUseDynamicIssuerResolution());
    }

    @Test
    public void readsConfiguredServiceAccountTokenForwardingFlag() {
        IdentityProviderModel model = new IdentityProviderModel();
        model.getConfig().put(KubernetesConstants.INCLUDE_SERVICE_ACCOUNT_TOKEN, "true");

        KubernetesIdentityProviderConfig config = new KubernetesIdentityProviderConfig(model);

        assertTrue(config.isIncludeServiceAccountToken());
    }
}
