package org.keycloak.broker.kubernetes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.ClientAssertionState;
import org.keycloak.authentication.authenticators.client.FederatedJWTClientAuthenticator;
import org.keycloak.broker.provider.ClientAssertionIdentityProviderFactory;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.Strings;

public class KubernetesClientAssertionStrategy implements ClientAssertionIdentityProviderFactory.ClientAssertionStrategy {

    @Override
    public boolean isSupportedAssertionType(String assertionType) {
        return OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT.equals(assertionType);
    }

    @Override
    public ClientAssertionIdentityProviderFactory.LookupResult lookup(ClientAuthenticationFlowContext context) throws Exception {
        ClientAssertionState clientAssertionState = context.getState(ClientAssertionState.class, ClientAssertionState.supplier());
        JsonWebToken token = clientAssertionState == null ? null : clientAssertionState.getToken();
        if (token == null || Strings.isEmpty(token.getIssuer()) || Strings.isEmpty(token.getSubject())) {
            return null;
        }

        List<ClientAssertionIdentityProviderFactory.LookupResult> matches = new ArrayList<>();
        List<ClientModel> clients = context.getSession().clients()
                .searchClientsByAttributes(context.getRealm(), Map.of(FederatedJWTClientAuthenticator.JWT_CREDENTIAL_SUBJECT_KEY, token.getSubject()), null, null)
                .filter(ClientModel::isEnabled)
                .toList();

        for (ClientModel client : clients) {
            if (!FederatedJWTClientAuthenticator.PROVIDER_ID.equals(client.getClientAuthenticatorType())) {
                continue;
            }

            String idpAlias = client.getAttribute(FederatedJWTClientAuthenticator.JWT_CREDENTIAL_ISSUER_KEY);
            if (Strings.isEmpty(idpAlias)) {
                continue;
            }

            IdentityProviderModel identityProvider = context.getSession().identityProviders().getByAlias(idpAlias);
            if (identityProvider == null || !identityProvider.isEnabled() || !KubernetesIdentityProviderFactory.PROVIDER_ID.equals(identityProvider.getProviderId())) {
                continue;
            }

            KubernetesIdentityProviderConfig config = new KubernetesIdentityProviderConfig(identityProvider);
            if (!config.isUseDynamicIssuerResolution() || token.getIssuer().equals(config.getIssuer())) {
                continue;
            }

            String discoveredIssuer = KubernetesIssuerResolver.resolveIssuer(context.getSession(), config, context.getRealm().getSslRequired());
            if (token.getIssuer().equals(discoveredIssuer)) {
                matches.add(new ClientAssertionIdentityProviderFactory.LookupResult(client, identityProvider));
            }
        }

        if (matches.size() > 1) {
            throw new IllegalStateException("Multiple Kubernetes clients match the same service account token subject and issuer");
        }

        return matches.isEmpty() ? null : matches.get(0);
    }
}
