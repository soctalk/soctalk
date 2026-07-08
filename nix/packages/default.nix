{ pkgs, lib, rev ? "dev" }:

{
  soctalk-api = import ./soctalk-api.nix { 
    inherit pkgs lib rev; 
  };
  
  soctalk-frontend = import ./soctalk-frontend.nix { 
    inherit pkgs; 
  };
  
  
  mock-endpoint = import ./mock-endpoint.nix { 
    inherit pkgs lib; 
  };
}
