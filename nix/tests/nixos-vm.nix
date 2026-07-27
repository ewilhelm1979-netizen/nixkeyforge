{
  pkgs,
  nixkeyforgeModule,
}:
pkgs.testers.runNixOSTest {
  name = "nixkeyforge-no-hardware";

  nodes.machine =
    { ... }:
    {
      imports = [ nixkeyforgeModule ];
      services.nixkeyforge.enable = true;
      system.stateVersion = "26.05";
    };

  testScript = ''
    machine.start()
    machine.succeed("nixkeyforge --format json doctor >/tmp/doctor.json || test $? -eq 20")
    machine.succeed("test -d /var/lib/nixkeyforge/plans")
    machine.succeed("stat -c %a /var/lib/nixkeyforge | grep -x 700")
    machine.fail("test -e /etc/u2f_mappings")
  '';
}
