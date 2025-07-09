import { expect } from "chai";
import { ethers } from "hardhat";
import "@openzeppelin/hardhat-upgrades";

const hre = require("hardhat");

describe("InfraSafe", function () {
  let infraSafe: any;
  let fallbackHandler: any;
  let owner: any;
  let signer1: any;
  let signer2: any;
  let user: any;

  beforeEach(async function () {
    [owner, signer1, signer2, user] = await ethers.getSigners();

    // Deploy FallbackHandler
    const FallbackHandler = await ethers.getContractFactory("FallbackHandler");
    fallbackHandler = await FallbackHandler.deploy(owner.address);
    await fallbackHandler.waitForDeployment();

    // Deploy InfraSafe
    const InfraSafe = await ethers.getContractFactory("InfraSafe");
    infraSafe = await hre.upgrades.deployProxy(
      InfraSafe,
      [[owner.address, signer1.address], 2, owner.address],
      { initializer: "initialize", kind: "uups" }
    );
    await infraSafe.waitForDeployment();
  });

  describe("Deployment", function () {
    it("Should set the right threshold", async function () {
      expect(await infraSafe.threshold()).to.equal(2);
    });

    it("Should set the right signers", async function () {
      expect(await infraSafe.isSigner(owner.address)).to.be.true;
      expect(await infraSafe.isSigner(signer1.address)).to.be.true;
      expect(await infraSafe.isSigner(signer2.address)).to.be.false;
    });

    it("Should have correct signer count", async function () {
      expect(await infraSafe.getSignerCount()).to.equal(2);
    });
  });

  describe("Signer Management", function () {
    it("Should allow admin to add signers", async function () {
      await infraSafe.connect(owner).addSigner(signer2.address);
      expect(await infraSafe.isSigner(signer2.address)).to.be.true;
      expect(await infraSafe.getSignerCount()).to.equal(3);
    });

    it("Should allow admin to remove signers", async function () {
      await infraSafe.connect(owner).removeSigner(signer1.address);
      expect(await infraSafe.isSigner(signer1.address)).to.be.false;
      expect(await infraSafe.getSignerCount()).to.equal(1);
    });

    it("Should not allow non-admin to add signers", async function () {
      await expect(
        infraSafe.connect(user).addSigner(signer2.address)
      ).to.be.reverted;
    });
  });

  describe("Threshold Management", function () {
    it("Should allow admin to change threshold", async function () {
      await infraSafe.connect(owner).changeThreshold(1);
      expect(await infraSafe.threshold()).to.equal(1);
    });

    it("Should not allow threshold greater than signer count", async function () {
      await expect(
        infraSafe.connect(owner).changeThreshold(5)
      ).to.be.revertedWithCustomError(infraSafe, "InvalidThreshold");
    });

    it("Should not allow zero threshold", async function () {
      await expect(
        infraSafe.connect(owner).changeThreshold(0)
      ).to.be.revertedWithCustomError(infraSafe, "InvalidThreshold");
    });
  });

  describe("Transaction Hash", function () {
    it("Should generate consistent transaction hashes", async function () {
      const to = user.address;
      const value = ethers.parseEther("1");
      const data = "0x";
      const nonce = 0;

      const hash1 = await infraSafe.getTransactionHash(to, value, data, nonce);
      const hash2 = await infraSafe.getTransactionHash(to, value, data, nonce);
      
      expect(hash1).to.equal(hash2);
    });
  });

  describe("Version", function () {
    it("Should return correct version", async function () {
      expect(await infraSafe.version()).to.equal("1.0.0");
    });
  });
});
