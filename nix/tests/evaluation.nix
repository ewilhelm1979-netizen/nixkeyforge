{ lib, ... }:
{
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
    };
  };

  assertions = [
    {
      assertion = true;
      message = "evaluation sentinel";
    }
  ];

  system.stateVersion = lib.mkDefault "26.05";
}
