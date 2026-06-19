// Flash loan attack simulation using Hardhat
const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  console.log("Simulating flash loan attack...");

  // Fork mainnet at specific block
  await hre.network.provider.request({
    method: "hardhat_reset",
    params: [{
      forking: {
        jsonRpcUrl: process.env.MAINNET_RPC,
        blockNumber: 18500000
      }
    }]
  });

  // Deploy flash loan receiver
  const FlashLoanReceiver = await hre.ethers.getContractFactory("FlashLoanReceiver");
  const receiver = await FlashLoanReceiver.deploy();
  await receiver.deployed();

  // Get Aave pool address
  const POOL_ADDRESS_PROVIDER = "0x2f39d218133AFaB8F2B819B1066c7E434Ad94E9e";
  const poolAddressProvider = await hre.ethers.getContractAt(
    "IPoolAddressesProvider", POOL_ADDRESS_PROVIDER
  );
  const poolAddress = await poolAddressProvider.getPool();
  console.log("Aave Pool:", poolAddress);

  // Execute flash loan
  const assets = ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"]; // WETH
  const amounts = [hre.ethers.utils.parseEther("10000")];
  const tx = await receiver.executeOperation(poolAddress, assets, amounts);
  console.log("Flash loan executed:", tx.hash);
}

main().catch(console.error);
