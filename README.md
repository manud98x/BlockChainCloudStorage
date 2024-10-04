
# Ethereum Smart Contract Deployment with Hardhat and Ganache

This project demonstrates how to deploy Ethereum smart contracts using **Hardhat** and **Ganache**. Follow the steps below to set up the environment and deploy the smart contracts.

## Prerequisites

Before starting, ensure the following are installed on your system:

1. **Node.js**: You can download and install Node.js from the official website: [https://nodejs.org/](https://nodejs.org/)
2. **Hardhat**: Install Hardhat to manage the Ethereum development environment.
3. **Ganache**: Install Ganache for creating a local Ethereum blockchain for testing.
   - **Ganache CLI**: Install via npm if needed:
     ```bash
     npm install -g ganache-cli
     ```

## Installation

### 1. Clone the Project Repository

First, clone the project to your local machine:

```bash
git clone <repository-url>
cd <repository-folder>
```

### 2. Install Project Dependencies

Ensure that the required dependencies are installed. Run:

```bash
npm install
```

### 3. Install Hardhat

If Hardhat is not already installed, you can install it using the following command:

```bash
npm install --save-dev hardhat
```

Set up Hardhat if it hasn't been configured yet by running:

```bash
npx hardhat
```

Follow the prompts to create a basic project structure.

## Setting Up Ganache

### 1. Start Ganache

- **Option 1: Ganache CLI**  
  Run the following command to start Ganache CLI:
  
  ```bash
  ganache-cli -p 8545
  ```

- **Option 2: Ganache GUI**  
  Open the Ganache GUI application and start a workspace. Make sure it's listening on port **8545** (default port).

## Configuring Hardhat

Make sure your `hardhat.config.js` file is properly configured to connect to the local Ganache network. Here’s an example configuration:

```js
require("@nomiclabs/hardhat-ethers");

module.exports = {
  solidity: "0.8.0",
  networks: {
    ganache: {
      url: "http://127.0.0.1:8545",
      accounts: ['YOUR_GANACHE_PRIVATE_KEY']  // Replace this with the private key of a Ganache account
    }
  }
};
```

To get the private key for a Ganache account:
- **Ganache CLI**: The private keys are displayed in the terminal when you start Ganache.
- **Ganache GUI**: Click on an account to view its private key.

## Compile and Deploy the Smart Contracts

### 1. Compile Contracts

Run the following command to compile the smart contracts:

```bash
npx hardhat compile
```

### 2. Deploy Contracts

Once the contracts are compiled, deploy them to the Ganache network:

```bash
npx hardhat run scripts/deploy.js --network ganache
```

After deployment, you will see the contract address in the output.

## Interact with the Deployed Contracts

### Using the Hardhat Console

You can interact with the deployed contracts using the Hardhat console. Run:

```bash
npx hardhat console --network ganache
```

In the console, you can access the deployed contract like this:

```js
const contract = await ethers.getContractAt("MyContract", "DEPLOYED_CONTRACT_ADDRESS");
```

Then, call any function on the contract, for example:

```js
await contract.someFunction();
```

## Common Issues

### 1. Insufficient Funds Error

If you encounter an "insufficient funds" error during deployment, check that the account you're using has enough ETH on the Ganache network. Ganache typically provides accounts with 100 ETH by default.

### 2. Missing Dependencies

If any dependencies are missing, run `npm install` to ensure all required packages are installed.

## Cleaning the Project

To clean up the compiled artifacts and cache:

```bash
npx hardhat clean
```

## Resetting Ganache

If you need to reset the local Ethereum blockchain, restart Ganache:

- **Ganache GUI**: Click **Restart** in the workspace.
- **Ganache CLI**: Stop and restart Ganache with `ganache-cli -p 8545`.

## Additional Resources

For more information on using Hardhat and Ganache, check out:

- [Hardhat Documentation](https://hardhat.org/getting-started/)
- [Ganache Documentation](https://trufflesuite.com/ganache/)
