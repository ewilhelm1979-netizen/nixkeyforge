{ ... }:
{
  # This module configures additive password + FIDO2 authentication only.
  # Credential enrollment remains a separate, mutable, out-of-store workflow.
  services.nixkeyforge = {
    enable = true;
    pam = {
      enable = true;
      services = [
        "login"
        "sddm"
        "kde"
      ];
      authFile = "/etc/u2f_mappings";
      requirePinVerification = true;
    };
  };
}
