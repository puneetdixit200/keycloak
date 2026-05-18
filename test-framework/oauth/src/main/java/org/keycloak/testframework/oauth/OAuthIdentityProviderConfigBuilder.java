package org.keycloak.testframework.oauth;

public class OAuthIdentityProviderConfigBuilder {

    private Mode mode = Mode.DEFAULT;
    private boolean jwkUse = true;
    private String issuer = "http://127.0.0.1:8500/idp";
    private String jwksUri = "http://127.0.0.1:8500/idp/jwks";
    private String kubernetesApiServerIssuer;

    public OAuthIdentityProviderConfigBuilder spiffe() {
        mode = Mode.SPIFFE;
        return this;
    }

    public OAuthIdentityProviderConfigBuilder kubernetes() {
        mode = Mode.KUBERNETES;
        return this;
    }

    public OAuthIdentityProviderConfigBuilder jwkUse(boolean jwkUse) {
        this.jwkUse = jwkUse;
        return this;
    }

    public OAuthIdentityProviderConfigBuilder issuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public OAuthIdentityProviderConfigBuilder jwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
        return this;
    }

    public OAuthIdentityProviderConfigBuilder kubernetesApiServerIssuer(String kubernetesApiServerIssuer) {
        this.kubernetesApiServerIssuer = kubernetesApiServerIssuer;
        return this;
    }

    public OAuthIdentityProviderConfiguration build() {
        return new OAuthIdentityProviderConfiguration(mode, jwkUse, issuer, jwksUri, kubernetesApiServerIssuer);
    }

    public record OAuthIdentityProviderConfiguration(Mode mode, boolean jwkUse, String issuer, String jwksUri, String kubernetesApiServerIssuer) {
    }

    public enum Mode {
        DEFAULT,
        SPIFFE,
        KUBERNETES
    }

}
