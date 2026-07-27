{ ... }:
{
  boot.initrd.systemd.enable = true;
  boot.initrd.luks.devices."luks-00000000-0000-0000-0000-000000000000" = {
    device = "/dev/disk/by-uuid/00000000-0000-0000-0000-000000000000";
    crypttabExtraOpts = [ "fido2-device=auto" ];
  };

  services.displayManager.sddm.enable = true;
  services.openssh.enable = false;

  security.pam = {
    u2f = {
      enable = true;
      settings.authfile = "/etc/u2f_mappings";
    };
    services.login = {
      u2f.enable = true;
      unixAuth = false;
    };
    services.sddm = {
      u2f.enable = true;
      unixAuth = false;
    };
  };
}
