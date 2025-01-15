// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {FeeQuoter} from "../../FeeQuoter.sol";
import {Client} from "../../libraries/Client.sol";
import {FeeQuoterSetup} from "./FeeQuoterSetup.t.sol";

contract FeeQuoter_parseEVMExtraArgsFromBytes is FeeQuoterSetup {
  FeeQuoter.DestChainConfig private s_destChainConfig;

  function setUp() public virtual override {
    super.setUp();
    s_destChainConfig = _generateFeeQuoterDestChainConfigArgs()[0].destChainConfig;
  }

  function test_EVMExtraArgsV1() public view {
    Client.EVMExtraArgsV1 memory inputArgs = Client.EVMExtraArgsV1({gasLimit: GAS_LIMIT});
    bytes memory inputExtraArgs = Client._argsToBytes(inputArgs);
    Client.EVMExtraArgsV2 memory expectedOutputArgs =
      Client.EVMExtraArgsV2({gasLimit: GAS_LIMIT, allowOutOfOrderExecution: false});

    vm.assertEq(
      abi.encode(s_feeQuoter.parseEVMExtraArgsFromBytes(inputExtraArgs, DEST_CHAIN_SELECTOR)),
      abi.encode(expectedOutputArgs)
    );
  }

  function test_EVMExtraArgsV2() public view {
    Client.EVMExtraArgsV2 memory inputArgs =
      Client.EVMExtraArgsV2({gasLimit: GAS_LIMIT, allowOutOfOrderExecution: true});
    bytes memory inputExtraArgs = Client._argsToBytes(inputArgs);

    vm.assertEq(
      abi.encode(s_feeQuoter.parseEVMExtraArgsFromBytes(inputExtraArgs, DEST_CHAIN_SELECTOR)), abi.encode(inputArgs)
    );
  }

  function test_EVMExtraArgsDefault() public view {
    Client.EVMExtraArgsV2 memory expectedOutputArgs =
      Client.EVMExtraArgsV2({gasLimit: s_destChainConfig.defaultTxGasLimit, allowOutOfOrderExecution: false});

    vm.assertEq(
      abi.encode(s_feeQuoter.parseEVMExtraArgsFromBytes("", DEST_CHAIN_SELECTOR)), abi.encode(expectedOutputArgs)
    );
  }

  // Reverts

  function test_RevertWhen_EVMExtraArgsInvalidExtraArgsTag() public {
    Client.EVMExtraArgsV2 memory inputArgs =
      Client.EVMExtraArgsV2({gasLimit: GAS_LIMIT, allowOutOfOrderExecution: true});
    bytes memory inputExtraArgs = Client._argsToBytes(inputArgs);
    // Invalidate selector
    inputExtraArgs[0] = bytes1(uint8(0));

    vm.expectRevert(FeeQuoter.InvalidExtraArgsTag.selector);
    s_feeQuoter.parseEVMExtraArgsFromBytes(inputExtraArgs, DEST_CHAIN_SELECTOR);
  }

  function test_RevertWhen_EVMExtraArgsEnforceOutOfOrder() public {
    Client.EVMExtraArgsV2 memory inputArgs =
      Client.EVMExtraArgsV2({gasLimit: GAS_LIMIT, allowOutOfOrderExecution: false});
    bytes memory inputExtraArgs = Client._argsToBytes(inputArgs);
    s_destChainConfig.enforceOutOfOrder = true;

    vm.expectRevert(FeeQuoter.ExtraArgOutOfOrderExecutionMustBeTrue.selector);
    s_feeQuoter.parseEVMExtraArgsFromBytes(inputExtraArgs, DEST_CHAIN_SELECTOR, true);
  }

  function test_RevertWhen_EVMExtraArgsGasLimitTooHigh() public {
    Client.EVMExtraArgsV2 memory inputArgs =
      Client.EVMExtraArgsV2({gasLimit: s_destChainConfig.maxPerMsgGasLimit + 1, allowOutOfOrderExecution: true});
    bytes memory inputExtraArgs = Client._argsToBytes(inputArgs);

    vm.expectRevert(FeeQuoter.MessageGasLimitTooHigh.selector);
    s_feeQuoter.parseEVMExtraArgsFromBytes(inputExtraArgs, DEST_CHAIN_SELECTOR);
  }
}
