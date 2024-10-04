require("@nomiclabs/hardhat-ethers");

module.exports = {
  solidity: "0.8.0",
  networks: {
    ganache: {
      url: "http://127.0.0.1:8545",  // Ganache RPC URL
      accounts: ["0xc4b1fbeed24d33aee2977fc9f925060162da889a53f094d36dac4b6569da1344"],  // Use private key from Ganache
    },
  },
};
