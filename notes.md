
FOR GRANT OPERATOR ROLES
cast send 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512 \
  "grantRole(bytes32,address)" \
  0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929 \
  0x70997970C51812dc3A010C7d01b50e0d17dc79C8 \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

FOR VERIFY IDENTITY
cast send 0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512   "verifyIdentity(address)"   0x70997970C51812dc3A010C7d01b50e0d17dc79C8   --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80   --rpc-url http://127.0.0.1:8545

FOR DEPLOY
forge script script/DeployAxiom.s.sol:DeployAxiomLocal --fork-url http://127.0.0.1:8545 --broadcast -vvvv