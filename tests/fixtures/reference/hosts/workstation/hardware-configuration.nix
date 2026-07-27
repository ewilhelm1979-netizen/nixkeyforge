{ ... }:
{
  fileSystems."/".device = "/dev/mapper/luks-00000000-0000-0000-0000-000000000000";
  boot.initrd.luks.devices."luks-00000000-0000-0000-0000-000000000000".device =
    "/dev/disk/by-uuid/00000000-0000-0000-0000-000000000000";
}
