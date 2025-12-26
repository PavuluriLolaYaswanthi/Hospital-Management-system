module.exports = {
  networks: {
    development: {
      host: "127.0.0.1",
      port: 7545,            // Ganache's default RPC port
      network_id: "*",       // Match any network id
    },
  },
  compilers: {
    solc: {
      version: "0.8.0",      // Solidity compiler version
    }
  }
};
