package org.keycloak.broker.kubernetes;


import org.keycloak.broker.oidc.IssuerValidation;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderType;
import org.keycloak.models.RealmModel;


public class KubernetesIdentityProviderConfig extends IdentityProviderModel implements IssuerValidation {

    public KubernetesIdentityProviderConfig() {
    }

    public KubernetesIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public String getIssuer() {
        return getConfig().get(ISSUER);
    }

    public boolean isUseDynamicIssuerResolution() {
        return Boolean.parseBoolean(getConfig().getOrDefault(KubernetesConstants.USE_DYNAMIC_ISSUER_RESOLUTION, Boolean.TRUE.toString()));
    }

    public void setUseDynamicIssuerResolution(boolean useDynamicIssuerResolution) {
        getConfig().put(KubernetesConstants.USE_DYNAMIC_ISSUER_RESOLUTION, String.valueOf(useDynamicIssuerResolution));
    }

    public boolean isIncludeServiceAccountToken() {
        return Boolean.parseBoolean(getConfig().getOrDefault(KubernetesConstants.INCLUDE_SERVICE_ACCOUNT_TOKEN, Boolean.FALSE.toString()));
    }

    public void setIncludeServiceAccountToken(boolean includeServiceAccountToken) {
        getConfig().put(KubernetesConstants.INCLUDE_SERVICE_ACCOUNT_TOKEN, String.valueOf(includeServiceAccountToken));
    }

    public int getAllowedClockSkew() {
        String allowedClockSkew = getConfig().get(ALLOWED_CLOCK_SKEW);
        if (allowedClockSkew == null || allowedClockSkew.isEmpty()) {
            return 0;
        }
        try {
            return Integer.parseInt(getConfig().get(ALLOWED_CLOCK_SKEW));
        } catch (NumberFormatException e) {
            // ignore it and use default
            return 0;
        }
    }

    @Override
    public Boolean isHideOnLogin() {
        return true;
    }

    @Override
    public void validate(RealmModel realm) {
        super.validate(realm);
        validateIssuer(realm, IdentityProviderType.CLIENT_ASSERTION);
    }
}
