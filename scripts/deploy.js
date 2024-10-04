async function main() {
        const [deployer] = await ethers.getSigners();
        console.log("Deploying contracts with the account:", deployer.address);
      
        const balance = await deployer.getBalance();
        console.log("Account balance:", balance.toString());
      
        const MyContract = await ethers.getContractFactory("FileSharing");  // Replace with your contract
        const contract = await MyContract.deploy();  // Add constructor arguments if needed
      
        console.log("Contract deployed to:", contract.address);
      }
      
      main()
        .then(() => process.exit(0))
        .catch(error => {
          console.error(error);
          process.exit(1);
        });
      
