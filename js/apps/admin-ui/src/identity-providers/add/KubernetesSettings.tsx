import { TextControl } from "@keycloak/keycloak-ui-shared";
import { useTranslation } from "react-i18next";
import { FormGroupField } from "../component/FormGroupField";
import { Controller, useFormContext } from "react-hook-form";
import { TimeSelector } from "../../components/time-selector/TimeSelector";
import IdentityProviderRepresentation from "libs/keycloak-admin-client/lib/defs/identityProviderRepresentation";
import { SwitchField } from "../component/SwitchField";

export const KubernetesSettings = () => {
  const { t } = useTranslation();
  const { control } = useFormContext<IdentityProviderRepresentation>();
  return (
    <>
      <TextControl
        name="alias"
        label={t("alias")}
        labelIcon={t("aliasHelp")}
        rules={{
          required: t("required"),
        }}
      />

      <TextControl
        name="config.issuer"
        labelIcon={t("kubernetesIssuerUrlHelp")}
        label={t("kubernetesIssuerUrl")}
      />
      <SwitchField
        field="config.useDynamicIssuerResolution"
        label="kubernetesUseDynamicIssuerResolution"
        defaultValue="true"
      />
      <SwitchField
        field="config.includeServiceAccountToken"
        label="kubernetesIncludeServiceAccountToken"
      />
      <FormGroupField label="fedClientAssertionMaxExp">
        <Controller
          name="config.fedClientAssertionMaxExp"
          defaultValue={""}
          control={control}
          render={({ field }) => (
            <TimeSelector
              className="kc-fed-client-assertion-max-expiration-time"
              data-testid="fed-client-assertion-max-expiration-time-input"
              value={field.value!}
              onChange={field.onChange}
              units={["minute", "hour", "day"]}
            />
          )}
        />
      </FormGroupField>
    </>
  );
};
